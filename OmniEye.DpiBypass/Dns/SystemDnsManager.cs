using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using Microsoft.Win32;

namespace OmniEye.DpiBypass.Dns;

/// <summary>
/// Manages system DNS configuration on active network interfaces,
/// connecting uncensored secure DoH providers (Cloudflare, Google, AdGuard, Quad9)
/// and ensuring clean restoration to original settings on exit.
/// </summary>
public static class SystemDnsManager
{
    private static readonly object _lock = new();
    private static readonly Dictionary<string, (bool WasDhcp, string[] StaticDns)> _backedUpAdapters = new(StringComparer.OrdinalIgnoreCase);

    public static bool IsConnected { get; private set; }
    public static string? ActiveProviderName { get; private set; }
    public static string? ActivePrimaryIp { get; private set; }

    public static event Action<bool, string>? DnsStateChanged;

    static SystemDnsManager()
    {
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            if (IsConnected)
            {
                RestoreDns();
            }
        };
    }

    /// <summary>
    /// Configures the active physical network adapters to use the specified secure DNS provider.
    /// </summary>
    public static bool ConnectDns(string providerName = "Cloudflare", string primaryIp = "1.1.1.1", string? secondaryIp = "1.0.0.1", string? dohTemplate = null)
    {
        lock (_lock)
        {
            try
            {
                var activeAdapters = GetActivePhysicalAdapters();
                if (activeAdapters.Count == 0)
                {
                    return false;
                }

                foreach (var adapter in activeAdapters)
                {
                    // 1. Backup if not already backed up
                    if (!_backedUpAdapters.ContainsKey(adapter.Name))
                    {
                        var backup = GetCurrentAdapterDns(adapter.Id);
                        _backedUpAdapters[adapter.Name] = backup;
                    }

                    // 2. Set primary DNS
                    RunNetsh($"interface ipv4 set dns name=\"{adapter.Name}\" static {primaryIp} primary");

                    // 3. Set secondary DNS if provided
                    if (!string.IsNullOrWhiteSpace(secondaryIp))
                    {
                        RunNetsh($"interface ipv4 add dns name=\"{adapter.Name}\" {secondaryIp} index=2");
                    }
                }

                // 4. In Windows 11, configure DoH encryption template if provided
                if (!string.IsNullOrWhiteSpace(dohTemplate))
                {
                    try
                    {
                        RunNetsh($"dns add encryption server={primaryIp} dohtemplate={dohTemplate} autoupgrade=yes udpfallback=yes");
                    }
                    catch { }
                }

                // 5. Flush DNS cache
                FlushDnsCache();

                IsConnected = true;
                ActiveProviderName = providerName;
                ActivePrimaryIp = primaryIp;
                DnsStateChanged?.Invoke(true, providerName);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Restores all modified network adapters to their original DNS settings (DHCP or static).
    /// </summary>
    public static bool RestoreDns()
    {
        lock (_lock)
        {
            if (!IsConnected && _backedUpAdapters.Count == 0) return true;

            try
            {
                foreach (var kvp in _backedUpAdapters)
                {
                    string adapterName = kvp.Key;
                    var (wasDhcp, staticDns) = kvp.Value;

                    if (wasDhcp || staticDns == null || staticDns.Length == 0)
                    {
                        RunNetsh($"interface ipv4 set dns name=\"{adapterName}\" dhcp");
                    }
                    else
                    {
                        RunNetsh($"interface ipv4 set dns name=\"{adapterName}\" static {staticDns[0]} primary");
                        for (int i = 1; i < staticDns.Length; i++)
                        {
                            RunNetsh($"interface ipv4 add dns name=\"{adapterName}\" {staticDns[i]} index={i + 1}");
                        }
                    }
                }

                _backedUpAdapters.Clear();
                FlushDnsCache();

                IsConnected = false;
                ActiveProviderName = null;
                ActivePrimaryIp = null;
                DnsStateChanged?.Invoke(false, string.Empty);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    private static (bool WasDhcp, string[] StaticDns) GetCurrentAdapterDns(string adapterGuid)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{adapterGuid}");
            if (key != null)
            {
                var nameServer = key.GetValue("NameServer") as string;
                if (!string.IsNullOrWhiteSpace(nameServer))
                {
                    var servers = nameServer.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (servers.Length > 0)
                    {
                        return (false, servers);
                    }
                }
            }
        }
        catch { }

        return (true, Array.Empty<string>());
    }

    public static List<(string Name, string Id)> GetActivePhysicalAdapters()
    {
        var list = new List<(string Name, string Id)>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;

                if (ni.NetworkInterfaceType != NetworkInterfaceType.Ethernet &&
                    ni.NetworkInterfaceType != NetworkInterfaceType.Wireless80211)
                {
                    continue;
                }

                var desc = ni.Description;
                if (desc.Contains("Virtual", StringComparison.OrdinalIgnoreCase) ||
                    desc.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase) ||
                    desc.Contains("Loopback", StringComparison.OrdinalIgnoreCase) ||
                    desc.Contains("TAP", StringComparison.OrdinalIgnoreCase) ||
                    desc.Contains("VPN", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                list.Add((ni.Name, ni.Id));
            }
        }
        catch { }
        return list;
    }

    private static void RunNetsh(string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "netsh.exe",
            Arguments = args,
            CreateNoWindow = true,
            UseShellExecute = false,
            WindowStyle = ProcessWindowStyle.Hidden
        };

        try
        {
            using var proc = Process.Start(psi);
            proc?.WaitForExit(2000);
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 740)
        {
            // Elevation required
            psi.UseShellExecute = true;
            psi.Verb = "runas";
            using var proc = Process.Start(psi);
            proc?.WaitForExit(3000);
        }
    }

    private static void FlushDnsCache()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "ipconfig.exe",
                Arguments = "/flushdns",
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(1500);
        }
        catch { }
    }
}
