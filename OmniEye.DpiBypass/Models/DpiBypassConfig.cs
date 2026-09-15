using System.Collections.Generic;

namespace OmniEye.DpiBypass.Models;

public class DpiBypassConfig
{
    public bool IsEnabled { get; set; } = true;
    public string ListenAddress { get; set; } = "127.0.0.1";
    public int ListenPort { get; set; } = 8085;
    
    // TLS Fragmentation options
    public bool EnableFragmentation { get; set; } = true;
    public int SplitPosition { get; set; } = 2; // Split after byte 2 of TLS Record
    public int SplitDelayMs { get; set; } = 2;   // Flush delay between segments
    
    // DNS options
    public bool EnableDoh { get; set; } = true;
    public int DnsTimeoutMs { get; set; } = 2500;
    
    // Windows System Proxy integration
    public bool EnableSystemProxy { get; set; } = false;
    public string ProxyBypassList { get; set; } = "<local>;localhost;127.*;10.*;192.168.*";
}
