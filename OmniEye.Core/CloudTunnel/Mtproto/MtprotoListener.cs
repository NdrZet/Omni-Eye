using System;
using System.Buffers;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using OmniEye.Core.CloudTunnel.WebSocket;
using OmniEye.Core.Models;

namespace OmniEye.Core.CloudTunnel.Mtproto;

public sealed class MtprotoListener : IAsyncDisposable
{
    private readonly CloudTunnelConfig _config;
    private readonly Action<long, long>? _onTrafficUpdated;
    private readonly Action<int>? _onConnectionCountChanged;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private int _activeConnections;

    public int ActiveConnections => _activeConnections;
    public bool IsRunning => _listener != null;

    public MtprotoListener(
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
        _listener = new TcpListener(ip, _config.MtprotoPort);
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
                byte[] handshakeBuffer = new byte[MtprotoHandshake.HandshakeLength];
                int read = 0;
                while (read < MtprotoHandshake.HandshakeLength)
                {
                    int r = await netStream.ReadAsync(handshakeBuffer.AsMemory(read, MtprotoHandshake.HandshakeLength - read), ct);
                    if (r == 0) return;
                    read += r;
                }

                byte[] secretBytes = Convert.FromHexString(_config.Secret);
                using var hs = MtprotoHandshake.TryParse(handshakeBuffer, secretBytes);
                if (hs == null)
                    return;

                string targetIp = _config.DcRedirects.TryGetValue(hs.DcId, out var redirect)
                    ? redirect
                    : "149.154.167.51";

                // 1. Try Cloudflare Worker WebSocket bridge
                CfWorkerClient? workerClient = null;
                if (_config.WorkerDomains.Count > 0)
                {
                    workerClient = await CfWorkerClient.ConnectAsync(_config.WorkerDomains, targetIp, hs.DcId, TimeSpan.FromSeconds(5), ct);
                }

                if (workerClient != null)
                {
                    await using (workerClient)
                    {
                        await workerClient.SendAsync(hs.RelayInit, ct);
                        await BridgeClientAndWorkerAsync(netStream, workerClient, hs, ct);
                    }
                    return;
                }

                // 2. Direct TCP Fallback
                using var upstreamClient = new TcpClient();
                try
                {
                    await upstreamClient.ConnectAsync(targetIp, 443, ct);
                    await using var upstreamStream = upstreamClient.GetStream();
                    await upstreamStream.WriteAsync(hs.RelayInit, ct);
                    await BridgeClientAndTcpAsync(netStream, upstreamStream, hs, ct);
                }
                catch { }
            }
        }
        catch { }
        finally
        {
            Interlocked.Decrement(ref _activeConnections);
            _onConnectionCountChanged?.Invoke(_activeConnections);
        }
    }

    private async Task BridgeClientAndWorkerAsync(
        NetworkStream clientStream,
        CfWorkerClient workerClient,
        HandshakeResult hs,
        CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var clientToWorker = Task.Run(async () =>
        {
            byte[] raw = ArrayPool<byte>.Shared.Rent(32768);
            byte[] plain = ArrayPool<byte>.Shared.Rent(32768);
            byte[] cipher = ArrayPool<byte>.Shared.Rent(32768);

            try
            {
                while (!cts.IsCancellationRequested)
                {
                    int n = await clientStream.ReadAsync(raw, cts.Token);
                    if (n == 0) break;

                    hs.ClientDecryptor.Process(raw.AsSpan(0, n), plain.AsSpan(0, n));
                    hs.TelegramEncryptor.Process(plain.AsSpan(0, n), cipher.AsSpan(0, n));

                    await workerClient.SendAsync(cipher.AsMemory(0, n), cts.Token);
                    _onTrafficUpdated?.Invoke(n, 0);
                }
            }
            catch { }
            finally
            {
                ArrayPool<byte>.Shared.Return(raw);
                ArrayPool<byte>.Shared.Return(plain);
                ArrayPool<byte>.Shared.Return(cipher);
                cts.Cancel();
            }
        }, cts.Token);

        var workerToClient = Task.Run(async () =>
        {
            byte[] raw = ArrayPool<byte>.Shared.Rent(32768);
            byte[] plain = ArrayPool<byte>.Shared.Rent(32768);
            byte[] cipher = ArrayPool<byte>.Shared.Rent(32768);

            try
            {
                while (!cts.IsCancellationRequested)
                {
                    int n = await workerClient.ReceiveAsync(raw, cts.Token);
                    if (n == 0) break;

                    hs.TelegramDecryptor.Process(raw.AsSpan(0, n), plain.AsSpan(0, n));
                    hs.ClientEncryptor.Process(plain.AsSpan(0, n), cipher.AsSpan(0, n));

                    await clientStream.WriteAsync(cipher.AsMemory(0, n), cts.Token);
                    _onTrafficUpdated?.Invoke(0, n);
                }
            }
            catch { }
            finally
            {
                ArrayPool<byte>.Shared.Return(raw);
                ArrayPool<byte>.Shared.Return(plain);
                ArrayPool<byte>.Shared.Return(cipher);
                cts.Cancel();
            }
        }, cts.Token);

        await Task.WhenAny(clientToWorker, workerToClient);
        cts.Cancel();
    }

    private async Task BridgeClientAndTcpAsync(
        NetworkStream clientStream,
        NetworkStream upstreamStream,
        HandshakeResult hs,
        CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var clientToUpstream = Task.Run(async () =>
        {
            byte[] raw = ArrayPool<byte>.Shared.Rent(32768);
            byte[] plain = ArrayPool<byte>.Shared.Rent(32768);
            byte[] cipher = ArrayPool<byte>.Shared.Rent(32768);

            try
            {
                while (!cts.IsCancellationRequested)
                {
                    int n = await clientStream.ReadAsync(raw, cts.Token);
                    if (n == 0) break;

                    hs.ClientDecryptor.Process(raw.AsSpan(0, n), plain.AsSpan(0, n));
                    hs.TelegramEncryptor.Process(plain.AsSpan(0, n), cipher.AsSpan(0, n));

                    await upstreamStream.WriteAsync(cipher.AsMemory(0, n), cts.Token);
                    _onTrafficUpdated?.Invoke(n, 0);
                }
            }
            catch { }
            finally
            {
                ArrayPool<byte>.Shared.Return(raw);
                ArrayPool<byte>.Shared.Return(plain);
                ArrayPool<byte>.Shared.Return(cipher);
                cts.Cancel();
            }
        }, cts.Token);

        var upstreamToClient = Task.Run(async () =>
        {
            byte[] raw = ArrayPool<byte>.Shared.Rent(32768);
            byte[] plain = ArrayPool<byte>.Shared.Rent(32768);
            byte[] cipher = ArrayPool<byte>.Shared.Rent(32768);

            try
            {
                while (!cts.IsCancellationRequested)
                {
                    int n = await upstreamStream.ReadAsync(raw, cts.Token);
                    if (n == 0) break;

                    hs.TelegramDecryptor.Process(raw.AsSpan(0, n), plain.AsSpan(0, n));
                    hs.ClientEncryptor.Process(plain.AsSpan(0, n), cipher.AsSpan(0, n));

                    await clientStream.WriteAsync(cipher.AsMemory(0, n), cts.Token);
                    _onTrafficUpdated?.Invoke(0, n);
                }
            }
            catch { }
            finally
            {
                ArrayPool<byte>.Shared.Return(raw);
                ArrayPool<byte>.Shared.Return(plain);
                ArrayPool<byte>.Shared.Return(cipher);
                cts.Cancel();
            }
        }, cts.Token);

        await Task.WhenAny(clientToUpstream, upstreamToClient);
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
