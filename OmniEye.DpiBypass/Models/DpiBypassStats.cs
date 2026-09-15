namespace OmniEye.DpiBypass.Models;

public class DpiBypassStats
{
    public int ActiveConnections { get; set; }
    public long TotalConnections { get; set; }
    public long TotalBytesTransferred { get; set; }
    public long DnsQueriesCount { get; set; }
    public long DnsCacheHits { get; set; }
}
