using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using OmniEye.Core.CloudTunnel.Mtproto;
using OmniEye.Core.CloudTunnel.Socks5;
using OmniEye.Core.CloudTunnel.SystemProxy;
using OmniEye.Core.Models;

namespace OmniEye.Core.CloudTunnel;

public sealed class CloudTunnelManager : IAsyncDisposable
{
    private CloudTunnelConfig _config;
    private MtprotoListener? _mtprotoListener;
    private Socks5Listener? _socks5Listener;
    private long _bytesUploaded;
    private long _bytesDownloaded;
    private long _workerPingMs = -1;
    private int _activeConnections;
    private CancellationTokenSource? _pingCts;

    public CloudTunnelConfig Config => _config;
    public bool IsRunning => _mtprotoListener?.IsRunning == true || _socks5Listener?.IsRunning == true;
    public long BytesUploaded => _bytesUploaded;
    public long BytesDownloaded => _bytesDownloaded;
    public long WorkerPingMs => _workerPingMs;
    public int ActiveConnections => _activeConnections;

    public event Action? StateChanged;

    public CloudTunnelManager(CloudTunnelConfig? config = null)
    {
        _config = config ?? new CloudTunnelConfig();
    }

    public void UpdateConfig(CloudTunnelConfig config)
    {
        bool wasRunning = IsRunning;
        if (wasRunning)
        {
            Stop();
        }

        _config = config;

        if (wasRunning || _config.IsEnabled)
        {
            Start();
        }
    }

    public void Start()
    {
        if (IsRunning)
            return;

        _config.IsEnabled = true;

        // Start MTProto listener
        _mtprotoListener = new MtprotoListener(
            _config,
            OnTrafficUpdated,
            OnConnectionsUpdated
        );
        _mtprotoListener.Start();

        // Start SOCKS5 listener if enabled
        if (_config.EnableSocks5)
        {
            _socks5Listener = new Socks5Listener(
                _config,
                OnTrafficUpdated,
                OnConnectionsUpdated
            );
            _socks5Listener.Start();
        }

        // Apply System Proxy if enabled
        if (_config.EnableSystemProxy)
        {
            WindowsProxyManager.EnableProxy(_config.Host, _config.Socks5Port, _config.BypassRussianTraffic);
        }

        StartPingMonitor();
        StateChanged?.Invoke();
    }

    public void Stop()
    {
        _config.IsEnabled = false;

        _pingCts?.Cancel();
        _pingCts = null;

        _mtprotoListener?.DisposeAsync().AsTask().Wait(1000);
        _mtprotoListener = null;

        _socks5Listener?.DisposeAsync().AsTask().Wait(1000);
        _socks5Listener = null;

        if (WindowsProxyManager.IsProxyEnabled())
        {
            WindowsProxyManager.DisableProxy();
        }

        _activeConnections = 0;
        StateChanged?.Invoke();
    }

    private void OnTrafficUpdated(long up, long down)
    {
        Interlocked.Add(ref _bytesUploaded, up);
        Interlocked.Add(ref _bytesDownloaded, down);
        StateChanged?.Invoke();
    }

    private void OnConnectionsUpdated(int count)
    {
        _activeConnections = (_mtprotoListener?.ActiveConnections ?? 0) + (_socks5Listener?.ActiveConnections ?? 0);
        StateChanged?.Invoke();
    }

    private void StartPingMonitor()
    {
        _pingCts?.Cancel();
        _pingCts = new CancellationTokenSource();
        var ct = _pingCts.Token;

        _ = Task.Run(async () =>
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };

            while (!ct.IsCancellationRequested)
            {
                if (_config.WorkerDomains.Count > 0)
                {
                    var domain = _config.WorkerDomains[0].Trim().Replace("https://", "").Replace("http://", "").TrimEnd('/');
                    var sw = Stopwatch.StartNew();
                    try
                    {
                        using var resp = await client.GetAsync($"https://{domain}", ct);
                        sw.Stop();
                        _workerPingMs = sw.ElapsedMilliseconds;
                    }
                    catch
                    {
                        _workerPingMs = -1;
                    }
                }
                else
                {
                    _workerPingMs = -1;
                }

                StateChanged?.Invoke();

                try
                {
                    await Task.Delay(15000, ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }, ct);
    }

    public async ValueTask DisposeAsync()
    {
        Stop();
        await Task.CompletedTask;
    }
}
