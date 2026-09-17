using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using OmniEye.Core.CloudTunnel.WebSocket;
using OmniEye.Core.Models;

namespace OmniEye.Core.CloudTunnel.Socks5;

/// <summary>
/// High performance SOCKS5 server for browsers, system proxy, terminal tools, and AI clients.
/// Supports both Direct connections (for .ru bypass) and Cloudflare Worker WebSocket tunnels.
/// </summary>
public sealed class Socks5Listener : IAsyncDisposable
{
    private readonly CloudTunnelConfig _config;
    private readonly Action<long, long>? _onTrafficUpdated;
    private readonly Action<int>? _onConnectionCountChanged;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private int _activeConnections;

    public int ActiveConnections => _activeConnections;
    public bool IsRunning => _listener != null;

    public Socks5Listener(
        CloudTunnelConfig config,
        Action<long, long>? onTrafficUpdated = null,
        Action<int>? onConnectionCountChanged = null)
    {
        _config = config;
        _onTrafficUpdated = onTrafficUpdated;
        _onConnectionCountChanged = onConnectionCountChanged;
    }

    public void Start()
    {
        if (_listener != null)
            return;

        _cts = new CancellationTokenSource();
        var ip = IPAddress.Parse(_config.Host);
        _listener = new TcpListener(ip, _config.Socks5Port);
        _listener.Start();

        _ = AcceptLoopAsync(_listener, _cts.Token);
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                _ = HandleClientAsync(client, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                if (ct.IsCancellationRequested)
                    break;
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        Interlocked.Increment(ref _activeConnections);
        _onConnectionCountChanged?.Invoke(_activeConnections);

        try
        {
            using (client)
            await using (var netStream = client.GetStream())
            {
                // 1. Negotiation Handshake (RFC 1928)
                byte[] authBuf = new byte[256];
                int read = await netStream.ReadAsync(authBuf.AsMemory(0, 2), ct);
                if (read < 2 || authBuf[0] != 0x05) return;

                int methodCount = authBuf[1];
                read = await netStream.ReadAsync(authBuf.AsMemory(0, methodCount), ct);
                if (read < methodCount) return;

                // Reply: SOCKS5 + NO AUTH REQUIRED (0x00)
                await netStream.WriteAsync(new byte[] { 0x05, 0x00 }, ct);

                // 2. Request Details [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
                byte[] reqHead = new byte[4];
                read = await netStream.ReadAsync(reqHead.AsMemory(0, 4), ct);
                if (read < 4 || reqHead[0] != 0x05 || reqHead[1] != 0x01) // Only CONNECT (0x01) supported
                {
                    await netStream.WriteAsync(new byte[] { 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, ct);
                    return;
                }

                byte atyp = reqHead[3];
                string targetHost;
                int targetPort;

                if (atyp == 0x01) // IPv4
                {
                    byte[] ipBytes = new byte[4];
                    await netStream.ReadExactlyAsync(ipBytes, ct);
                    targetHost = new IPAddress(ipBytes).ToString();
                }
                else if (atyp == 0x03) // Domain name
                {
                    int domainLen = netStream.ReadByte();
                    if (domainLen <= 0) return;
                    byte[] domainBytes = new byte[domainLen];
                    await netStream.ReadExactlyAsync(domainBytes, ct);
                    targetHost = Encoding.ASCII.GetString(domainBytes);
                }
                else if (atyp == 0x04) // IPv6
                {
                    byte[] ipBytes = new byte[16];
                    await netStream.ReadExactlyAsync(ipBytes, ct);
                    targetHost = new IPAddress(ipBytes).ToString();
                }
                else
                {
                    return;
                }

                byte[] portBytes = new byte[2];
                await netStream.ReadExactlyAsync(portBytes, ct);
                targetPort = BinaryPrimitives.ReadUInt16BigEndian(portBytes);

                // 3. Routing decision: Direct vs Cloudflare Tunnel
                bool isBypassed = _config.BypassRussianTraffic &&
                    (targetHost.EndsWith(".ru", StringComparison.OrdinalIgnoreCase) ||
                     targetHost.EndsWith(".рф", StringComparison.OrdinalIgnoreCase) ||
                     targetHost.EndsWith(".xn--p1ai", StringComparison.OrdinalIgnoreCase) ||
                     targetHost.Contains("gosuslugi.ru", StringComparison.OrdinalIgnoreCase) ||
                     targetHost.Contains("sberbank.ru", StringComparison.OrdinalIgnoreCase) ||
                     targetHost.Contains("tbank.ru", StringComparison.OrdinalIgnoreCase) ||
                     targetHost.Contains("yandex.ru", StringComparison.OrdinalIgnoreCase));

                // Try CF Worker if not bypassed and domains configured
                CfWorkerClient? workerClient = null;
                if (!isBypassed && _config.WorkerDomains.Count > 0)
                {
                    workerClient = await CfWorkerClient.ConnectAsync(_config.WorkerDomains, targetHost, targetPort, TimeSpan.FromSeconds(5), ct);
                }

                if (workerClient != null)
                {
                    await using (workerClient)
                    {
                        // SOCKS5 success reply
                        await netStream.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, ct);
                        await PipeClientAndWorkerAsync(netStream, workerClient, ct);
                    }
                    return;
                }

                // Direct TCP connection fallback
                using var directClient = new TcpClient();
                try
                {
                    await directClient.ConnectAsync(targetHost, targetPort, ct);
                    await using var directStream = directClient.GetStream();

                    // SOCKS5 success reply
                    await netStream.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, ct);
                    await PipeStreamsAsync(netStream, directStream, ct);
                }
                catch
                {
                    // General failure
                    try
                    {
                        await netStream.WriteAsync(new byte[] { 0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, ct);
                    }
                    catch { }
                }
            }
        }
        catch { }
        finally
        {
            Interlocked.Decrement(ref _activeConnections);
            _onConnectionCountChanged?.Invoke(_activeConnections);
        }
    }

    private async Task PipeClientAndWorkerAsync(NetworkStream clientStream, CfWorkerClient workerClient, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var c2w = Task.Run(async () =>
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(32768);
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    int n = await clientStream.ReadAsync(buf, cts.Token);
                    if (n == 0) break;
                    await workerClient.SendAsync(buf.AsMemory(0, n), cts.Token);
                    _onTrafficUpdated?.Invoke(n, 0);
                }
            }
            catch { }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
                cts.Cancel();
            }
        }, cts.Token);

        var w2c = Task.Run(async () =>
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(32768);
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    int n = await workerClient.ReceiveAsync(buf, cts.Token);
                    if (n == 0) break;
                    await clientStream.WriteAsync(buf.AsMemory(0, n), cts.Token);
                    _onTrafficUpdated?.Invoke(0, n);
                }
            }
            catch { }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
                cts.Cancel();
            }
        }, cts.Token);

        await Task.WhenAny(c2w, w2c);
        cts.Cancel();
    }

    private async Task PipeStreamsAsync(NetworkStream s1, NetworkStream s2, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var t1 = Task.Run(async () =>
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(32768);
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    int n = await s1.ReadAsync(buf, cts.Token);
                    if (n == 0) break;
                    await s2.WriteAsync(buf.AsMemory(0, n), cts.Token);
                    _onTrafficUpdated?.Invoke(n, 0);
                }
            }
            catch { }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
                cts.Cancel();
            }
        }, cts.Token);

        var t2 = Task.Run(async () =>
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(32768);
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    int n = await s2.ReadAsync(buf, cts.Token);
                    if (n == 0) break;
                    await s1.WriteAsync(buf.AsMemory(0, n), cts.Token);
                    _onTrafficUpdated?.Invoke(0, n);
                }
            }
            catch { }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
                cts.Cancel();
            }
        }, cts.Token);

        await Task.WhenAny(t1, t2);
        cts.Cancel();
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _listener?.Stop();
        _listener = null;
        await Task.CompletedTask;
    }
}
