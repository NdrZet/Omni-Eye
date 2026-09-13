using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using OmniEye.Core.Configuration;
using OmniEye.Core.Models;

namespace OmniEye.Core.Ipc;

/// <summary>
/// Asynchronous Named Pipe client for communicating with OmniEyeSvc.
/// </summary>
public class IpcClient : IDisposable
{
    private readonly OmniEyeConfig _config;
    private NamedPipeClientStream? _pipeClient;
    private StreamWriter? _writer;
    private StreamReader? _reader;
    private CancellationTokenSource? _listenCts;
    private Task? _readLoopTask;
    private bool _isConnected;

    public bool IsConnected => _isConnected && (_pipeClient?.IsConnected ?? false);

    public event Action<bool>? ConnectionChanged;
    public event Action<InjectionPromptNotification>? InjectionPromptReceived;

    public IpcClient(OmniEyeConfig? config = null)
    {
        _config = config ?? new OmniEyeConfig();
    }

    public async Task<bool> ConnectAsync(int timeoutMs = 3000)
    {
        try
        {
            if (_pipeClient != null)
            {
                await DisconnectAsync();
            }

            _pipeClient = new NamedPipeClientStream(
                ".",
                _config.PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            await _pipeClient.ConnectAsync(timeoutMs);

            _writer = new StreamWriter(_pipeClient, Encoding.UTF8, bufferSize: 4096, leaveOpen: true) { AutoFlush = true };
            _reader = new StreamReader(_pipeClient, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);

            _isConnected = true;
            ConnectionChanged?.Invoke(true);

            _listenCts = new CancellationTokenSource();
            _readLoopTask = Task.Run(() => ReadLoopAsync(_listenCts.Token));

            return true;
        }
        catch
        {
            _isConnected = false;
            ConnectionChanged?.Invoke(false);
            return false;
        }
    }

    private async Task ReadLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested && _isConnected && _reader != null)
        {
            try
            {
                var line = await _reader.ReadLineAsync(token);
                if (line == null)
                    break;

                var msg = Newtonsoft.Json.JsonConvert.DeserializeObject<IpcMessage>(line);
                if (msg == null)
                    continue;

                if (msg.Type == IpcMessageTypes.InjectionPromptNotification)
                {
                    var notification = msg.GetPayload<InjectionPromptNotification>();
                    if (notification != null)
                    {
                        InjectionPromptReceived?.Invoke(notification);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                break;
            }
        }

        _isConnected = false;
        ConnectionChanged?.Invoke(false);
    }

    public async Task<StatusResponse?> GetStatusAsync(int timeoutMs = 3000)
    {
        var req = IpcMessage.Create(IpcMessageTypes.GetStatusRequest, new object());
        var res = await SendRequestAsync<StatusResponse>(req, IpcMessageTypes.GetStatusResponse, timeoutMs);
        return res;
    }

    public async Task<WhitelistResponse?> GetWhitelistAsync(int timeoutMs = 3000)
    {
        var req = IpcMessage.Create(IpcMessageTypes.GetWhitelistRequest, new object());
        var res = await SendRequestAsync<WhitelistResponse>(req, IpcMessageTypes.GetWhitelistResponse, timeoutMs);
        return res;
    }

    public async Task<AddWhitelistResponse?> AddToWhitelistAsync(string filePath, bool bypassSignature, int timeoutMs = 5000)
    {
        var req = IpcMessage.Create(IpcMessageTypes.AddWhitelistRequest, new AddWhitelistRequest
        {
            FilePath = filePath,
            BypassSignatureCheck = bypassSignature
        });
        var res = await SendRequestAsync<AddWhitelistResponse>(req, IpcMessageTypes.AddWhitelistResponse, timeoutMs);
        return res;
    }

    public async Task<RemoveWhitelistResponse?> RemoveFromWhitelistAsync(int id, int timeoutMs = 3000)
    {
        var req = IpcMessage.Create(IpcMessageTypes.RemoveWhitelistRequest, new RemoveWhitelistRequest { Id = id });
        var res = await SendRequestAsync<RemoveWhitelistResponse>(req, IpcMessageTypes.RemoveWhitelistResponse, timeoutMs);
        return res;
    }

    public async Task<SetFirewallPolicyResponse?> SetFirewallPolicyAsync(bool blockOutbound, int timeoutMs = 4000)
    {
        var req = IpcMessage.Create(IpcMessageTypes.SetFirewallPolicyRequest, new SetFirewallPolicyRequest
        {
            BlockOutbound = blockOutbound
        });
        var res = await SendRequestAsync<SetFirewallPolicyResponse>(req, IpcMessageTypes.SetFirewallPolicyResponse, timeoutMs);
        return res;
    }

    public async Task SendPromptDecisionAsync(string promptId, string action)
    {
        if (!IsConnected || _writer == null)
            return;

        var req = IpcMessage.Create(IpcMessageTypes.InjectionPromptAction, new InjectionPromptAction
        {
            PromptId = promptId,
            Action = action
        });

        var json = Newtonsoft.Json.JsonConvert.SerializeObject(req);
        await _writer.WriteLineAsync(json);
    }

    private async Task<T?> SendRequestAsync<T>(IpcMessage request, string expectedResponseType, int timeoutMs)
    {
        if (!IsConnected)
        {
            var reconnected = await ConnectAsync(1000);
            if (!reconnected || _writer == null || _pipeClient == null)
                return default;
        }

        try
        {
            using var rpcClient = new NamedPipeClientStream(".", _config.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await rpcClient.ConnectAsync(timeoutMs);

            using var w = new StreamWriter(rpcClient, Encoding.UTF8, bufferSize: 4096, leaveOpen: true) { AutoFlush = true };
            using var r = new StreamReader(rpcClient, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);

            var json = Newtonsoft.Json.JsonConvert.SerializeObject(request);
            await w.WriteLineAsync(json);

            using var cts = new CancellationTokenSource(timeoutMs);
            var line = await r.ReadLineAsync(cts.Token);
            if (line == null)
                return default;

            var responseMsg = Newtonsoft.Json.JsonConvert.DeserializeObject<IpcMessage>(line);
            if (responseMsg?.Type == expectedResponseType)
            {
                return responseMsg.GetPayload<T>();
            }
        }
        catch
        {
            // Timeout or connection error
        }

        return default;
    }

    public async Task DisconnectAsync()
    {
        _listenCts?.Cancel();
        _isConnected = false;

        if (_pipeClient != null)
        {
            try { _pipeClient.Dispose(); } catch { }
            _pipeClient = null;
        }

        if (_readLoopTask != null)
        {
            try { await _readLoopTask; } catch { }
            _readLoopTask = null;
        }
    }

    public void Dispose()
    {
        DisconnectAsync().GetAwaiter().GetResult();
        _listenCts?.Dispose();
    }
}
