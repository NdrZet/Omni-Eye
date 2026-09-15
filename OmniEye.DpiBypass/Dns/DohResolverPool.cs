using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using OmniEye.DpiBypass.Models;

namespace OmniEye.DpiBypass.Dns;

public class DohResolverPool : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ConcurrentDictionary<string, (List<IPAddress> Addresses, DateTime Expiry)> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Timer _healthCheckTimer;
    private bool _disposed;

    public List<DohServerInfo> Servers { get; } = new();
    public long TotalQueriesCount { get; private set; }
    public long CacheHitsCount { get; private set; }

    public DohResolverPool()
    {
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(2.5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            EnableMultipleHttp2Connections = true,
            SslOptions = new SslClientAuthenticationOptions
            {
                // Accept certificates issued for IP SANs (1.1.1.1, 8.8.8.8, 9.9.9.9) or domain names
                RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                {
                    if (errors == SslPolicyErrors.None) return true;
                    // Allow IP SAN mismatches if cert is valid otherwise
                    if (errors == SslPolicyErrors.RemoteCertificateNameMismatch) return true;
                    return false;
                }
            }
        };

        _httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(3)
        };

        // Initialize top tier DoH servers with direct IP addresses
        Servers.Add(new DohServerInfo("Cloudflare", "https://1.1.1.1/dns-query", "1.1.1.1", "cloudflare-dns.com", "1.0.0.1"));
        Servers.Add(new DohServerInfo("Cloudflare-Backup", "https://1.0.0.1/dns-query", "1.0.0.1", "cloudflare-dns.com", "1.1.1.1"));
        Servers.Add(new DohServerInfo("Google", "https://8.8.8.8/dns-query", "8.8.8.8", "dns.google", "8.8.4.4"));
        Servers.Add(new DohServerInfo("Quad9", "https://9.9.9.9/dns-query", "9.9.9.9", "dns.quad9.net", "149.112.112.112"));
        Servers.Add(new DohServerInfo("AdGuard", "https://94.140.14.14/dns-query", "94.140.14.14", "dns.adguard-dns.com", "94.140.15.15"));

        _healthCheckTimer = new Timer(async _ => await RunHealthChecksAsync(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(25));
    }

    public async Task<IPAddress?> ResolveAsync(string hostname, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(hostname)) return null;

        // If hostname is already an IP address
        if (IPAddress.TryParse(hostname, out var directIp))
        {
            return directIp;
        }

        TotalQueriesCount++;

        // 1. Check in-memory cache
        if (_cache.TryGetValue(hostname, out var cached) && cached.Expiry > DateTime.UtcNow && cached.Addresses.Count > 0)
        {
            CacheHitsCount++;
            return cached.Addresses[0];
        }

        // 2. Select candidates for the race (prefer active, low-latency servers)
        var candidates = Servers
            .Where(s => s.IsEnabled && !s.IsDegraded)
            .OrderBy(s => s.LatencyMs > 0 ? s.LatencyMs : 999)
            .Take(3)
            .ToList();

        if (candidates.Count == 0)
        {
            candidates = Servers.Where(s => s.IsEnabled).ToList();
        }

        if (candidates.Count == 0)
        {
            return await FallbackSystemResolveAsync(hostname);
        }

        // 3. Concurrent Racing (Happy Eyeballs DoH query)
        byte[] queryBytes = DnsWireFormatHelper.BuildQuery(hostname);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(3000);

        var tasks = candidates.Select(server => QueryServerAsync(server, queryBytes, hostname, cts.Token)).ToList();

        while (tasks.Count > 0)
        {
            var completedTask = await Task.WhenAny(tasks);
            tasks.Remove(completedTask);

            try
            {
                var result = await completedTask;
                if (result != null && result.Value.Addresses.Count > 0)
                {
                    // Winner found! Cancel remaining tasks
                    cts.Cancel();

                    uint ttl = Math.Clamp(result.Value.MinTtl, 10, 86400);
                    _cache[hostname] = (result.Value.Addresses, DateTime.UtcNow.AddSeconds(ttl));
                    return result.Value.Addresses[0];
                }
            }
            catch
            {
                // Server failed, continue waiting for other servers in the race
            }
        }

        // If all DoH candidates failed, fallback to system DNS
        return await FallbackSystemResolveAsync(hostname);
    }

    private async Task<(List<IPAddress> Addresses, uint MinTtl)?> QueryServerAsync(
        DohServerInfo server, byte[] queryBytes, string hostname, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, server.Url);
            request.Headers.Host = server.HostHeader;
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
            request.Content = new ByteArrayContent(queryBytes);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseContentRead, ct);
            sw.Stop();

            if (response.IsSuccessStatusCode)
            {
                byte[] respBytes = await response.Content.ReadAsByteArrayAsync(ct);
                var (addresses, minTtl) = DnsWireFormatHelper.ParseResponse(respBytes);

                server.LatencyMs = sw.ElapsedMilliseconds;
                server.ConsecutiveFailures = 0;
                server.LastChecked = DateTime.UtcNow;

                if (addresses.Count > 0)
                {
                    return (addresses, minTtl);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Cancelled because another server won the race
            throw;
        }
        catch
        {
            server.ConsecutiveFailures++;
            server.LastChecked = DateTime.UtcNow;
            throw;
        }

        return null;
    }

    public async Task RunHealthChecksAsync()
    {
        if (_disposed) return;

        byte[] canaryQuery = DnsWireFormatHelper.BuildQuery("cloudflare.com");
        foreach (var server in Servers.Where(s => s.IsEnabled))
        {
            try
            {
                using var cts = new CancellationTokenSource(2000);
                var sw = Stopwatch.StartNew();
                using var request = new HttpRequestMessage(HttpMethod.Post, server.Url);
                request.Headers.Host = server.HostHeader;
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
                request.Content = new ByteArrayContent(canaryQuery);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

                using var response = await _httpClient.SendAsync(request, cts.Token);
                sw.Stop();

                if (response.IsSuccessStatusCode)
                {
                    server.LatencyMs = sw.ElapsedMilliseconds;
                    server.ConsecutiveFailures = 0;
                }
                else
                {
                    server.ConsecutiveFailures++;
                }
            }
            catch
            {
                server.ConsecutiveFailures++;
            }
            finally
            {
                server.LastChecked = DateTime.UtcNow;
            }
        }
    }

    private static async Task<IPAddress?> FallbackSystemResolveAsync(string hostname)
    {
        try
        {
            var addrs = await System.Net.Dns.GetHostAddressesAsync(hostname);
            return addrs.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) ?? addrs.FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _healthCheckTimer.Dispose();
        _httpClient.Dispose();
        GC.SuppressFinalize(this);
    }
}
