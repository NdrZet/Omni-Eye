using System;

namespace OmniEye.Core.Models;

public enum NetworkProtocol
{
    Tcp,
    Udp
}

public enum ZeroTrustEnforcementStatus
{
    Whitelisted,
    SystemException,
    Blocked,
    Permissive
}

public class NetworkConnectionInfo
{
    public NetworkProtocol Protocol { get; set; }
    public string ProtocolName => Protocol == NetworkProtocol.Tcp ? "TCP" : "UDP";

    public string LocalAddress { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }

    public string State { get; set; } = string.Empty;

    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ProcessPath { get; set; } = string.Empty;

    public ZeroTrustEnforcementStatus EnforcementStatus { get; set; }

    public string LocalEndpoint => $"{LocalAddress}:{LocalPort}";

    public string RemoteEndpoint
    {
        get
        {
            if (RemotePort <= 0 || string.IsNullOrEmpty(RemoteAddress) || RemoteAddress == "0.0.0.0" || RemoteAddress == "::")
            {
                return "*:*";
            }

            string portHint = RemotePort switch
            {
                80 => " (HTTP)",
                443 => " (HTTPS)",
                53 => " (DNS)",
                853 => " (DoT)",
                22 => " (SSH)",
                123 => " (NTP)",
                _ => string.Empty
            };

            return $"{RemoteAddress}:{RemotePort}{portHint}";
        }
    }

    public bool CanAddToWhitelist => EnforcementStatus != ZeroTrustEnforcementStatus.Whitelisted &&
                                     !string.IsNullOrEmpty(ProcessPath) &&
                                     !ProcessPath.StartsWith("[", StringComparison.Ordinal);

    public string StatusResourceKey => EnforcementStatus switch
    {
        ZeroTrustEnforcementStatus.Whitelisted => "NetMon_StatusWhitelisted",
        ZeroTrustEnforcementStatus.Blocked => "NetMon_StatusBlocked",
        ZeroTrustEnforcementStatus.SystemException => "NetMon_StatusException",
        _ => "NetMon_StatusPermissive"
    };

    public string StatusText { get; set; } = string.Empty;

    public string StatusBadgeBackground => EnforcementStatus switch
    {
        ZeroTrustEnforcementStatus.Whitelisted => "#264CE8A3",
        ZeroTrustEnforcementStatus.Blocked => "#26FF99A4",
        ZeroTrustEnforcementStatus.SystemException => "#26FFC83B",
        _ => "#20CCCCCC"
    };

    public string StatusBadgeBorder => EnforcementStatus switch
    {
        ZeroTrustEnforcementStatus.Whitelisted => "#604CE8A3",
        ZeroTrustEnforcementStatus.Blocked => "#60FF99A4",
        ZeroTrustEnforcementStatus.SystemException => "#60FFC83B",
        _ => "#40CCCCCC"
    };

    public string StatusBadgeForeground => EnforcementStatus switch
    {
        ZeroTrustEnforcementStatus.Whitelisted => "#4CE8A3",
        ZeroTrustEnforcementStatus.Blocked => "#FF99A4",
        ZeroTrustEnforcementStatus.SystemException => "#FFC83B",
        _ => "#CCCCCC"
    };

    public string ProtocolBadgeBackground => Protocol == NetworkProtocol.Tcp ? "#264CC2FF" : "#26B47CFF";
    public string ProtocolBadgeBorder => Protocol == NetworkProtocol.Tcp ? "#504CC2FF" : "#50B47CFF";
    public string ProtocolBadgeForeground => Protocol == NetworkProtocol.Tcp ? "#4CC2FF" : "#D1A8FF";
}
