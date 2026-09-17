using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;

namespace OmniEye.Core.CloudTunnel.WebSocket;

/// <summary>
/// Connects to Cloudflare Worker WebSocket endpoint: wss://{domain}/apiws?dst={dst}&dc={dc}
/// and provides bi-directional streaming for Telegram MTProto and SOCKS5.
/// </summary>
public sealed class CfWorkerClient : IAsyncDisposable
{
    private readonly ClientWebSocket _ws = new();
    private readonly string _connectedDomain;

    public string ConnectedDomain => _connectedDomain;
    public WebSocketState State => _ws.State;

    private CfWorkerClient(string domain)
    {
        _connectedDomain = domain;
        _ws.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);
    }

    /// <summary>
    /// Attempts to connect to one of the provided Cloudflare worker domains.
    /// </summary>
    public static async Task<CfWorkerClient?> ConnectAsync(
        IReadOnlyList<string> domains,
        string dstIp,
        int dcId,
        TimeSpan timeout,
        CancellationToken ct = default)
    {
        if (domains == null || domains.Count == 0)
            return null;

        foreach (var domain in domains)
        {
            var cleanDomain = domain.Trim().Replace("https://", "").Replace("http://", "").TrimEnd('/');
            if (string.IsNullOrWhiteSpace(cleanDomain))
                continue;

            var uri = new Uri($"wss://{cleanDomain}/apiws?dst={dstIp}&dc={dcId}");
            var client = new CfWorkerClient(cleanDomain);

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeout);

                await client._ws.ConnectAsync(uri, cts.Token);
                if (client._ws.State == WebSocketState.Open)
                    return client;
            }
            catch
            {
                await client.DisposeAsync();
            }
        }

        return null;
    }

    public async ValueTask SendAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        if (_ws.State == WebSocketState.Open)
        {
            await _ws.SendAsync(buffer, WebSocketMessageType.Binary, true, ct);
        }
    }

    public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_ws.State != WebSocketState.Open)
            return 0;

        var result = await _ws.ReceiveAsync(buffer, ct);
        if (result.MessageType == WebSocketMessageType.Close)
        {
            try
            {
                await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", ct);
            }
            catch { }
            return 0;
        }

        return result.Count;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (_ws.State == WebSocketState.Open)
            {
                await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", CancellationToken.None);
            }
        }
        catch { }

        _ws.Dispose();
    }
}
