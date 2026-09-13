using System;
using System.Collections.Concurrent;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using OmniEye.Core.Configuration;
using OmniEye.Core.Models;
using OmniEye.Core.Storage;
using OmniEyeSvc.Network;

namespace OmniEyeSvc.Ipc;

/// <summary>
/// High-performance multi-client Named Pipe IPC server.
/// Dispatches requests from OmniEyeTray and broadcasts real-time security alerts.
/// </summary>
public class IpcServer : IDisposable
{
    private readonly OmniEyeConfig _config;
    private readonly DatabaseManager _dbManager;
    private readonly FirewallEnforcer _firewall;
    private readonly ILogger<IpcServer> _logger;
    private readonly DateTime _startTime = DateTime.UtcNow;

    private readonly ConcurrentDictionary<string, NamedPipeServerStream> _activeClients = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<string>> _pendingPromptResponses = new();

    private CancellationTokenSource? _serverCts;
    private Task? _listenerTask;
    private int _blockedAttemptsCount = 0;

    public int BlockedAttemptsCount => _blockedAttemptsCount;

    public void IncrementBlockedAttempts() => Interlocked.Increment(ref _blockedAttemptsCount);

    public IpcServer(
        OmniEyeConfig config,
        DatabaseManager dbManager,
        FirewallEnforcer firewall,
        ILogger<IpcServer> logger)
    {
        _config = config;
        _dbManager = dbManager;
        _firewall = firewall;
        _logger = logger;
    }

    public void Start()
    {
        _serverCts = new CancellationTokenSource();
        _listenerTask = Task.Run(() => ListenLoop(_serverCts.Token));
        _logger.LogInformation("IPC Named Pipe Server started on \\\\.\\pipe\\{PipeName}", _config.PipeName);
    }

    private PipeSecurity CreatePipeSecurity()
    {
        var ps = new PipeSecurity();

        var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

        ps.AddAccessRule(new PipeAccessRule(systemSid, PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(adminSid, PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(usersSid, PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, AccessControlType.Allow));

        return ps;
    }

    private async Task ListenLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                var pipeSecurity = CreatePipeSecurity();
                var serverStream = NamedPipeServerStreamAcl.Create(
                    _config.PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    inBufferSize: 65536,
                    outBufferSize: 65536,
                    pipeSecurity);

                await serverStream.WaitForConnectionAsync(token);

                var clientId = Guid.NewGuid().ToString();
                _activeClients[clientId] = serverStream;
                _logger.LogInformation("Client connected: {ClientId}", clientId);

                _ = Task.Run(() => HandleClientAsync(clientId, serverStream, token), token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error accepting IPC connection: {Message}", ex.Message);
                await Task.Delay(1000, token);
            }
        }
    }

    private async Task HandleClientAsync(string clientId, NamedPipeServerStream stream, CancellationToken token)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
        using var writer = new StreamWriter(stream, Encoding.UTF8, bufferSize: 4096, leaveOpen: true) { AutoFlush = true };

        try
        {
            while (!token.IsCancellationRequested && stream.IsConnected)
            {
                var line = await reader.ReadLineAsync(token);
                if (line == null)
                    break;

                var request = Newtonsoft.Json.JsonConvert.DeserializeObject<IpcMessage>(line);
                if (request == null)
                    continue;

                var response = HandleMessage(request);
                if (response != null)
                {
                    var responseJson = Newtonsoft.Json.JsonConvert.SerializeObject(response);
                    await writer.WriteLineAsync(responseJson.AsMemory(), token);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.LogDebug("Client {ClientId} disconnected: {Message}", clientId, ex.Message);
        }
        finally
        {
            _activeClients.TryRemove(clientId, out _);
            stream.Dispose();
            _logger.LogInformation("Client {ClientId} session ended.", clientId);
        }
    }

    private IpcMessage? HandleMessage(IpcMessage request)
    {
        switch (request.Type)
        {
            case IpcMessageTypes.GetStatusRequest:
                var status = new StatusResponse
                {
                    IsRunning = true,
                    DeveloperMode = _config.DeveloperMode,
                    OutboundBlocked = _firewall.IsEnforced,
                    WhitelistCount = _dbManager.GetWhitelist().Count,
                    BlockedAttemptsCount = _blockedAttemptsCount,
                    Uptime = DateTime.UtcNow - _startTime,
                    ServerTime = DateTime.UtcNow
                };
                return IpcMessage.Create(IpcMessageTypes.GetStatusResponse, status, request.CorrelationId);

            case IpcMessageTypes.GetWhitelistRequest:
                var list = _dbManager.GetWhitelist();
                var wlResponse = new WhitelistResponse { Entries = list };
                return IpcMessage.Create(IpcMessageTypes.GetWhitelistResponse, wlResponse, request.CorrelationId);

            case IpcMessageTypes.AddWhitelistRequest:
                var addReq = request.GetPayload<AddWhitelistRequest>();
                if (addReq == null || string.IsNullOrWhiteSpace(addReq.FilePath))
                {
                    return IpcMessage.Create(IpcMessageTypes.AddWhitelistResponse, new AddWhitelistResponse
                    {
                        Success = false,
                        Message = "Invalid file path."
                    }, request.CorrelationId);
                }

                try
                {
                    var entry = _dbManager.AddEntry(addReq.FilePath, addReq.BypassSignatureCheck);
                    _firewall.AddApplicationRule(entry);
                    return IpcMessage.Create(IpcMessageTypes.AddWhitelistResponse, new AddWhitelistResponse
                    {
                        Success = true,
                        Message = "Added to whitelist and firewall successfully.",
                        Entry = entry
                    }, request.CorrelationId);
                }
                catch (Exception ex)
                {
                    return IpcMessage.Create(IpcMessageTypes.AddWhitelistResponse, new AddWhitelistResponse
                    {
                        Success = false,
                        Message = ex.Message
                    }, request.CorrelationId);
                }

            case IpcMessageTypes.RemoveWhitelistRequest:
                var remReq = request.GetPayload<RemoveWhitelistRequest>();
                if (remReq == null)
                    return null;

                bool removed = false;
                if (remReq.Id > 0)
                {
                    _firewall.RemoveApplicationRule(remReq.Id);
                    removed = _dbManager.RemoveEntry(remReq.Id);
                }
                else if (!string.IsNullOrEmpty(remReq.FilePath))
                {
                    var found = _dbManager.GetWhitelist().Find(x => string.Equals(x.FilePath, remReq.FilePath, StringComparison.OrdinalIgnoreCase));
                    if (found != null)
                    {
                        _firewall.RemoveApplicationRule(found.Id);
                        removed = _dbManager.RemoveEntry(found.Id);
                    }
                }

                return IpcMessage.Create(IpcMessageTypes.RemoveWhitelistResponse, new RemoveWhitelistResponse
                {
                    Success = removed,
                    Message = removed ? "Application removed from whitelist." : "Entry not found."
                }, request.CorrelationId);

            case IpcMessageTypes.SetFirewallPolicyRequest:
                var polReq = request.GetPayload<SetFirewallPolicyRequest>();
                if (polReq == null)
                {
                    return IpcMessage.Create(IpcMessageTypes.SetFirewallPolicyResponse, new SetFirewallPolicyResponse
                    {
                        Success = false,
                        OutboundBlocked = _firewall.IsEnforced,
                        Message = "Invalid firewall policy request."
                    }, request.CorrelationId);
                }

                try
                {
                    _firewall.SetOutboundBlocked(polReq.BlockOutbound);
                    return IpcMessage.Create(IpcMessageTypes.SetFirewallPolicyResponse, new SetFirewallPolicyResponse
                    {
                        Success = true,
                        OutboundBlocked = _firewall.IsEnforced,
                        Message = polReq.BlockOutbound 
                            ? "Default outbound policy set to BLOCK (Zero-Trust)." 
                            : "Default outbound policy set to ALLOW (Permissive)."
                    }, request.CorrelationId);
                }
                catch (Exception ex)
                {
                    return IpcMessage.Create(IpcMessageTypes.SetFirewallPolicyResponse, new SetFirewallPolicyResponse
                    {
                        Success = false,
                        OutboundBlocked = _firewall.IsEnforced,
                        Message = ex.Message
                    }, request.CorrelationId);
                }

            case IpcMessageTypes.InjectionPromptAction:
                var action = request.GetPayload<InjectionPromptAction>();
                if (action != null && !string.IsNullOrEmpty(action.PromptId))
                {
                    if (_pendingPromptResponses.TryGetValue(action.PromptId, out var tcs))
                    {
                        tcs.TrySetResult(action.Action);
                    }
                }
                return null;

            default:
                _logger.LogWarning("Unknown IPC message type: {Type}", request.Type);
                return null;
        }
    }

    /// <summary>
    /// Sends an injection prompt notification to connected GUI clients and waits for user decision
    /// or timeout. Default action on timeout is "kill".
    /// </summary>
    public async Task<string> PromptUserForInjectionDecisionAsync(InjectionPromptNotification notification, TimeSpan timeout)
    {
        var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingPromptResponses[notification.PromptId] = tcs;

        try
        {
            var msg = IpcMessage.Create(IpcMessageTypes.InjectionPromptNotification, notification);
            var json = Newtonsoft.Json.JsonConvert.SerializeObject(msg);

            // Broadcast to all active clients
            bool sent = false;
            foreach (var kvp in _activeClients)
            {
                try
                {
                    if (kvp.Value.IsConnected)
                    {
                        var writer = new StreamWriter(kvp.Value, Encoding.UTF8, bufferSize: 4096, leaveOpen: true) { AutoFlush = true };
                        await writer.WriteLineAsync(json);
                        sent = true;
                    }
                }
                catch { }
            }

            if (!sent)
            {
                _logger.LogWarning("No GUI client connected to receive Prompt {PromptId}. Falling back to default 'kill'.", notification.PromptId);
                return "kill";
            }

            using var cts = new CancellationTokenSource(timeout);
            using (cts.Token.Register(() => tcs.TrySetResult("kill")))
            {
                return await tcs.Task;
            }
        }
        finally
        {
            _pendingPromptResponses.TryRemove(notification.PromptId, out _);
        }
    }

    public void Stop()
    {
        _serverCts?.Cancel();
        foreach (var client in _activeClients.Values)
        {
            try { client.Dispose(); } catch { }
        }
        _activeClients.Clear();
    }

    public void Dispose()
    {
        Stop();
        _serverCts?.Dispose();
    }
}
