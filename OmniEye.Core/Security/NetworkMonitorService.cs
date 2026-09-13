using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using OmniEye.Core.Models;

namespace OmniEye.Core.Security;

public static class NetworkMonitorService
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        int reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucLocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucRemoteAddr;
        public uint dwRemoteScopeId;
        public uint dwRemotePort;
        public uint dwState;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucLocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }

    private static readonly ConcurrentDictionary<int, (string Name, string Path, DateTime CachedAt)> ProcessCache = new();

    public static List<NetworkConnectionInfo> GetActiveConnections(
        IEnumerable<string>? whitelistedPaths = null,
        bool isOutboundBlocked = true)
    {
        var whitelistSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var whitelistNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (whitelistedPaths != null)
        {
            foreach (var p in whitelistedPaths)
            {
                if (!string.IsNullOrEmpty(p))
                {
                    whitelistSet.Add(p);
                    var fname = Path.GetFileName(p);
                    if (!string.IsNullOrEmpty(fname))
                    {
                        whitelistNames.Add(fname);
                    }
                }
            }
        }

        var results = new List<NetworkConnectionInfo>();

        // 1. TCP IPv4
        GetTcp4Connections(results);

        // 2. TCP IPv6
        GetTcp6Connections(results);

        // 3. UDP IPv4
        GetUdp4Connections(results);

        // 4. UDP IPv6
        GetUdp6Connections(results);

        // Correlate with process info and Zero-Trust whitelist
        foreach (var conn in results)
        {
            var (procName, procPath) = ResolveProcess(conn.ProcessId);
            conn.ProcessName = procName;
            conn.ProcessPath = procPath;

            conn.EnforcementStatus = EvaluateStatus(conn, procName, procPath, whitelistSet, whitelistNames, isOutboundBlocked);
        }

        // Sort: ESTABLISHED connections first, then listening TCP, then UDP
        results.Sort((a, b) =>
        {
            int RankState(NetworkConnectionInfo c)
            {
                if (c.State == "ESTABLISHED") return 1;
                if (c.State == "SYN_SENT" || c.State == "SYN_RCVD") return 2;
                if (c.State == "LISTENING") return 3;
                if (c.Protocol == NetworkProtocol.Udp) return 4;
                return 5;
            }

            int rankA = RankState(a);
            int rankB = RankState(b);
            if (rankA != rankB) return rankA.CompareTo(rankB);

            int cmpProc = string.Compare(a.ProcessName, b.ProcessName, StringComparison.OrdinalIgnoreCase);
            if (cmpProc != 0) return cmpProc;

            return a.LocalPort.CompareTo(b.LocalPort);
        });

        return results;
    }

    private static void GetTcp4Connections(List<NetworkConnectionInfo> results)
    {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufferSize <= 0) return;

        var pTable = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint ret = GetExtendedTcpTable(pTable, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(pTable);
            var rowPtr = IntPtr.Add(pTable, 4);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                var localIp = new IPAddress(BitConverter.GetBytes(row.dwLocalAddr)).ToString();
                var remoteIp = new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)).ToString();
                int localPort = ConvertPort(row.dwLocalPort);
                int remotePort = ConvertPort(row.dwRemotePort);

                results.Add(new NetworkConnectionInfo
                {
                    Protocol = NetworkProtocol.Tcp,
                    LocalAddress = localIp,
                    LocalPort = localPort,
                    RemoteAddress = remoteIp,
                    RemotePort = remotePort,
                    State = ResolveTcpState(row.dwState),
                    ProcessId = (int)row.dwOwningPid
                });
            }
        }
        catch { }
        finally
        {
            Marshal.FreeHGlobal(pTable);
        }
    }

    private static void GetTcp6Connections(List<NetworkConnectionInfo> results)
    {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufferSize <= 0) return;

        var pTable = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint ret = GetExtendedTcpTable(pTable, ref bufferSize, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(pTable);
            var rowPtr = IntPtr.Add(pTable, 4);
            int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                var localIp = new IPAddress(row.ucLocalAddr).ToString();
                var remoteIp = new IPAddress(row.ucRemoteAddr).ToString();
                int localPort = ConvertPort(row.dwLocalPort);
                int remotePort = ConvertPort(row.dwRemotePort);

                results.Add(new NetworkConnectionInfo
                {
                    Protocol = NetworkProtocol.Tcp,
                    LocalAddress = localIp,
                    LocalPort = localPort,
                    RemoteAddress = remoteIp,
                    RemotePort = remotePort,
                    State = ResolveTcpState(row.dwState),
                    ProcessId = (int)row.dwOwningPid
                });
            }
        }
        catch { }
        finally
        {
            Marshal.FreeHGlobal(pTable);
        }
    }

    private static void GetUdp4Connections(List<NetworkConnectionInfo> results)
    {
        int bufferSize = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (bufferSize <= 0) return;

        var pTable = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint ret = GetExtendedUdpTable(pTable, ref bufferSize, true, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(pTable);
            var rowPtr = IntPtr.Add(pTable, 4);
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                var localIp = new IPAddress(BitConverter.GetBytes(row.dwLocalAddr)).ToString();
                int localPort = ConvertPort(row.dwLocalPort);

                results.Add(new NetworkConnectionInfo
                {
                    Protocol = NetworkProtocol.Udp,
                    LocalAddress = localIp,
                    LocalPort = localPort,
                    RemoteAddress = "*",
                    RemotePort = 0,
                    State = "UDP",
                    ProcessId = (int)row.dwOwningPid
                });
            }
        }
        catch { }
        finally
        {
            Marshal.FreeHGlobal(pTable);
        }
    }

    private static void GetUdp6Connections(List<NetworkConnectionInfo> results)
    {
        int bufferSize = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        if (bufferSize <= 0) return;

        var pTable = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint ret = GetExtendedUdpTable(pTable, ref bufferSize, true, AF_INET6, UDP_TABLE_OWNER_PID, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(pTable);
            var rowPtr = IntPtr.Add(pTable, 4);
            int rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                var localIp = new IPAddress(row.ucLocalAddr).ToString();
                int localPort = ConvertPort(row.dwLocalPort);

                results.Add(new NetworkConnectionInfo
                {
                    Protocol = NetworkProtocol.Udp,
                    LocalAddress = localIp,
                    LocalPort = localPort,
                    RemoteAddress = "*",
                    RemotePort = 0,
                    State = "UDP",
                    ProcessId = (int)row.dwOwningPid
                });
            }
        }
        catch { }
        finally
        {
            Marshal.FreeHGlobal(pTable);
        }
    }

    private static int ConvertPort(uint dwPort)
    {
        return (int)(((dwPort & 0xFF) << 8) | ((dwPort >> 8) & 0xFF));
    }

    private static string ResolveTcpState(uint state)
    {
        return state switch
        {
            1 => "CLOSED",
            2 => "LISTENING",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => $"STATE_{state}"
        };
    }

    public static (string Name, string Path) ResolveProcess(int pid)
    {
        if (pid == 0) return ("System Idle", string.Empty);
        if (pid == 4) return ("System", "ntoskrnl.exe");

        if (ProcessCache.TryGetValue(pid, out var cached) && (DateTime.UtcNow - cached.CachedAt).TotalSeconds < 15)
        {
            return (cached.Name, cached.Path);
        }

        string name = string.Empty;
        string path = string.Empty;

        try
        {
            using var proc = Process.GetProcessById(pid);
            name = proc.ProcessName;
        }
        catch
        {
            name = $"PID {pid}";
        }

        try
        {
            path = NtDllNative.GetProcessExecutablePath(pid);
            if (!string.IsNullOrEmpty(path) && (string.IsNullOrEmpty(name) || name.StartsWith("PID ")))
            {
                name = Path.GetFileNameWithoutExtension(path);
            }
        }
        catch
        {
            path = string.Empty;
        }

        ProcessCache[pid] = (name, path, DateTime.UtcNow);
        return (name, path);
    }

    private static ZeroTrustEnforcementStatus EvaluateStatus(
        NetworkConnectionInfo conn,
        string procName,
        string procPath,
        HashSet<string> whitelistSet,
        HashSet<string> whitelistNames,
        bool isOutboundBlocked)
    {
        // 1. Whitelist match
        if (!string.IsNullOrEmpty(procPath) && whitelistSet.Contains(procPath))
        {
            return ZeroTrustEnforcementStatus.Whitelisted;
        }

        var fileName = Path.GetFileName(procPath);
        if (!string.IsNullOrEmpty(fileName) && whitelistNames.Contains(fileName))
        {
            return ZeroTrustEnforcementStatus.Whitelisted;
        }

        if (!string.IsNullOrEmpty(procName) && whitelistNames.Contains(procName + ".exe"))
        {
            return ZeroTrustEnforcementStatus.Whitelisted;
        }

        // 2. System Exceptions (DNS, DHCP, Windows Core Services)
        if (conn.RemotePort == 53 || conn.LocalPort == 53 || conn.LocalPort == 67 || conn.LocalPort == 68 || conn.RemotePort == 67 || conn.RemotePort == 68)
        {
            return ZeroTrustEnforcementStatus.SystemException;
        }

        if (string.Equals(procName, "svchost", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(procName, "lsass", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(procName, "System", StringComparison.OrdinalIgnoreCase) ||
            conn.ProcessId == 4)
        {
            return ZeroTrustEnforcementStatus.SystemException;
        }

        // 3. Fallback based on Outbound Policy
        if (isOutboundBlocked)
        {
            return ZeroTrustEnforcementStatus.Blocked;
        }

        return ZeroTrustEnforcementStatus.Permissive;
    }
}
