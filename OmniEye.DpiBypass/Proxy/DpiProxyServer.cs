using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using OmniEye.DpiBypass.Dns;
using OmniEye.DpiBypass.Models;
using OmniEye.DpiBypass.Tls;

namespace OmniEye.DpiBypass.Proxy;

public class DpiProxyServer : IDisposable
{
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private int _activeConnections;
    private bool _disposed;

    public DpiBypassConfig Config { get; }
    public DohResolverPool ResolverPool { get; }
    public DpiBypassStats Stats { get; } = new();
    public bool IsRunning { get; private set; }

    public DpiProxyServer(DpiBypassConfig? config = null, DohResolverPool? resolverPool = null)
    {
        Config = config ?? new DpiBypassConfig();
        ResolverPool = resolverPool ?? new DohResolverPool();
    }

    public void Start()
    {
        if (IsRunning) return;

        _cts = new CancellationTokenSource();
        var ip = IPAddress.Parse(Config.ListenAddress);
        _listener = new TcpListener(ip, Config.ListenPort);
        _listener.Start(128);
        IsRunning = true;

        _ = AcceptLoopAsync(_cts.Token);
    }

    public void Stop()
    {
        if (!IsRunning) return;
        IsRunning = false;

        _cts?.Cancel();
        try
        {
            _listener?.Stop();
        }
        catch { }

        Interlocked.Exchange(ref _activeConnections, 0);
        Stats.ActiveConnections = 0;
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && IsRunning)
        {
            try
            {
                var client = await _listener!.AcceptTcpClientAsync(ct);
                _ = Task.Run(() => HandleClientAsync(client, ct), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception)
            {
                if (!IsRunning) break;
                await Task.Delay(100, ct);
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        Interlocked.Increment(ref _activeConnections);
        Stats.ActiveConnections = _activeConnections;
        Stats.TotalConnections++;

        try
        {
            client.NoDelay = true;
            using var clientStream = client.GetStream();

            // Read the HTTP CONNECT request
            var reader = new StreamReader(clientStream, Encoding.ASCII, leaveOpen: true);
            string? firstLine = await reader.ReadLineAsync(ct);

            if (string.IsNullOrEmpty(firstLine)) return;

            // e.g. "CONNECT example.com:443 HTTP/1.1"
            var parts = firstLine.Split(' ');
            if (parts.Length < 2) return;

            string method = parts[0].ToUpperInvariant();
            string target = parts[1];

            // Drain remaining headers until empty line
            string? header;
            while (!string.IsNullOrEmpty(header = await reader.ReadLineAsync(ct))) { }

            string host;
            int port = 443;

            if (method == "CONNECT")
            {
                var hostParts = target.Split(':');
                host = hostParts[0];
                if (hostParts.Length > 1 && int.TryParse(hostParts[1], out int p))
                {
                    port = p;
                }
            }
            else
            {
                // Fallback for standard HTTP requests if any
                if (Uri.TryCreate(target, UriKind.Absolute, out var uri))
                {
                    host = uri.Host;
                    port = uri.Port;
                }
                else
                {
                    return;
                }
            }

            // 1. Resolve host via DoH Resolver Pool
            IPAddress? targetIp;
            if (Config.EnableDoh)
            {
                targetIp = await ResolverPool.ResolveAsync(host, ct);
            }
            else
            {
                var addrs = await System.Net.Dns.GetHostAddressesAsync(host, ct);
                targetIp = addrs.FirstOrDefault();
            }

            if (targetIp == null)
            {
                byte[] error502 = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\n\r\n");
                await clientStream.WriteAsync(error502, ct);
                return;
            }

            // 2. Connect to the remote server
            using var remoteClient = new TcpClient();
            remoteClient.NoDelay = true;
            await remoteClient.ConnectAsync(targetIp, port, ct);
            using var remoteStream = remoteClient.GetStream();

            // 3. Confirm connection to the client
            byte[] okResponse = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
            await clientStream.WriteAsync(okResponse, ct);
            await clientStream.FlushAsync(ct);

            // 4. Intercept the first packet (TLS ClientHello) and fragment if applicable
            byte[] initialBuffer = new byte[8192];
            int initialBytesRead = await clientStream.ReadAsync(initialBuffer, ct);

            if (initialBytesRead > 0)
            {
                if (Config.EnableFragmentation && TlsClientHelloParser.IsClientHello(initialBuffer, initialBytesRead))
                {
                    int splitOffset = TlsClientHelloParser.CalculateSplitOffset(initialBuffer, initialBytesRead, Config.SplitPosition);

                    // Send fragment 1
                    await remoteStream.WriteAsync(initialBuffer.AsMemory(0, splitOffset), ct);
                    await remoteStream.FlushAsync(ct);

                    // Micro-delay between segments
                    if (Config.SplitDelayMs > 0)
                    {
                        await Task.Delay(Config.SplitDelayMs, ct);
                    }

                    // Send fragment 2
                    await remoteStream.WriteAsync(initialBuffer.AsMemory(splitOffset, initialBytesRead - splitOffset), ct);
                    await remoteStream.FlushAsync(ct);
                }
                else
                {
                    // Regular packet pass-through
                    await remoteStream.WriteAsync(initialBuffer.AsMemory(0, initialBytesRead), ct);
                    await remoteStream.FlushAsync(ct);
                }

                Stats.TotalBytesTransferred += initialBytesRead;
            }

            // 5. Bidirectional streaming
            var clientToRemote = RelayStreamAsync(clientStream, remoteStream, ct);
            var remoteToClient = RelayStreamAsync(remoteStream, clientStream, ct);

            await Task.WhenAny(clientToRemote, remoteToClient);
        }
        catch
        {
            // Normal socket disconnect or timeout
        }
        finally
        {
            try { client.Close(); } catch { }
            Interlocked.Decrement(ref _activeConnections);
            Stats.ActiveConnections = _activeConnections;
        }
    }

    private async Task RelayStreamAsync(Stream source, Stream destination, CancellationToken ct)
    {
        byte[] buffer = new byte[16384];
        int bytesRead;

        while ((bytesRead = await source.ReadAsync(buffer, ct)) > 0)
        {
            await destination.WriteAsync(buffer.AsMemory(0, bytesRead), ct);
            Stats.TotalBytesTransferred += bytesRead;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
        ResolverPool.Dispose();
        GC.SuppressFinalize(this);
    }
}
