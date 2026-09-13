using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using OmniEye.Core.Configuration;
using OmniEye.Core.Models;
using OmniEye.Core.Security;
using OmniEye.Core.Storage;
using OmniEyeSvc.Ipc;

namespace OmniEyeSvc.Monitor;

/// <summary>
/// Anti-Injection Monitor utilizes Event Tracing for Windows (ETW) Kernel tracing
/// to detect process/thread injection attempts targeting whitelisted applications.
/// Implements the "Freeze & Prompt" defense mechanism via NtSuspendProcess.
/// </summary>
public class AntiInjectionMonitor : IDisposable
{
    private readonly OmniEyeConfig _config;
    private readonly DatabaseManager _dbManager;
    private readonly IpcServer _ipcServer;
    private readonly ILogger<AntiInjectionMonitor> _logger;

    private readonly ConcurrentDictionary<int, (int ParentPid, DateTime StartTime)> _recentlySpawnedProcesses = new();

    private TraceEventSession? _etwSession;
    private Task? _etwTask;
    private CancellationTokenSource? _monitorCts;
    private const string SessionName = "OmniEyeKernelTraceSession";

    public AntiInjectionMonitor(
        OmniEyeConfig config,
        DatabaseManager dbManager,
        IpcServer ipcServer,
        ILogger<AntiInjectionMonitor> logger)
    {
        _config = config;
        _dbManager = dbManager;
        _ipcServer = ipcServer;
        _logger = logger;
    }

    public void Start()
    {
        _monitorCts = new CancellationTokenSource();
        _etwTask = Task.Run(() => RunEtwSession(_monitorCts.Token));
    }

    private void RunEtwSession(CancellationToken token)
    {
        try
        {
            _logger.LogInformation("Starting ETW Kernel Session for Anti-Injection monitoring...");

            // TraceEventSession.GetActiveSessionNames() check
            var existingSession = TraceEventSession.GetActiveSession(SessionName);
            existingSession?.Stop();

            _etwSession = new TraceEventSession(SessionName);
            _etwSession.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.Thread |
                KernelTraceEventParser.Keywords.ImageLoad);

            _etwSession.Source.Kernel.ProcessStart += OnProcessStart;
            _etwSession.Source.Kernel.ThreadStart += OnThreadStart;

            _logger.LogInformation("ETW Kernel Session active. Monitoring remote injection events.");
            _etwSession.Source.Process();
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning("ETW Kernel tracing requires Administrator / SYSTEM privileges: {Message}", ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start ETW Kernel Session: {Message}", ex.Message);
        }
    }

    private void OnProcessStart(ProcessTraceData data)
    {
        try
        {
            _recentlySpawnedProcesses[data.ProcessID] = (data.ParentID, DateTime.UtcNow);

            // Housekeeping: remove entries older than 30 seconds
            if (_recentlySpawnedProcesses.Count > 256)
            {
                var now = DateTime.UtcNow;
                foreach (var kvp in _recentlySpawnedProcesses)
                {
                    if ((now - kvp.Value.StartTime).TotalSeconds > 30)
                    {
                        _recentlySpawnedProcesses.TryRemove(kvp.Key, out _);
                    }
                }
            }
        }
        catch { }
    }

    private void OnThreadStart(ThreadTraceData data)
    {
        try
        {
            int targetPid = data.ProcessID;
            int sourcePid = data.ParentProcessID;

            // Ignore intra-process thread creation
            if (targetPid <= 4 || sourcePid <= 4 || targetPid == sourcePid)
                return;

            // Don't monitor ourselves
            int currentPid = Environment.ProcessId;
            if (targetPid == currentPid || sourcePid == currentPid)
                return;

            // 1. Check if this is normal process startup (initial thread of a newly created process)
            if (_recentlySpawnedProcesses.TryGetValue(targetPid, out var spawnInfo))
            {
                if (spawnInfo.ParentPid == sourcePid && (DateTime.UtcNow - spawnInfo.StartTime).TotalSeconds < 10)
                {
                    // Normal process startup by parent, not a remote injection
                    return;
                }
            }

            // Resolve target process executable path
            string targetPath = NtDllNative.GetProcessExecutablePath(targetPid);
            if (string.IsNullOrEmpty(targetPath) || targetPath.StartsWith("["))
                return;

            // Check if target is a whitelisted application
            if (!_dbManager.IsPathWhitelisted(targetPath))
                return;

            // Target is a whitelisted application! Check source process.
            string sourcePath = NtDllNative.GetProcessExecutablePath(sourcePid);

            // If source is whitelisted, allow
            if (_dbManager.IsPathWhitelisted(sourcePath))
                return;

            // 2. Allow legitimate Windows shell and system launchers
            var sourceExeName = Path.GetFileName(sourcePath);
            if (string.Equals(sourceExeName, "explorer.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(sourceExeName, "services.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(sourceExeName, "svchost.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(sourceExeName, "RuntimeBroker.exe", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            // 3. Allow legitimate sub-processes within the same application hierarchy (e.g. Discord, updaters)
            if (IsSameApplicationHierarchy(sourcePath, targetPath))
            {
                return;
            }

            _logger.LogWarning("POTENTIAL INJECTION DETECTED: Untrusted Process {SourcePid} ({SourcePath}) -> Whitelisted Process {TargetPid} ({TargetPath})",
                sourcePid, sourcePath, targetPid, targetPath);

            // Trigger Freeze & Prompt in background
            _ = Task.Run(() => ExecuteFreezeAndPromptAsync(sourcePid, sourcePath, targetPid, targetPath));
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Error processing thread start event: {Message}", ex.Message);
        }
    }

    private static bool IsSameApplicationHierarchy(string path1, string path2)
    {
        if (string.IsNullOrEmpty(path1) || string.IsNullOrEmpty(path2) || path1.StartsWith("[") || path2.StartsWith("["))
            return false;

        try
        {
            var dir1 = Path.GetDirectoryName(path1);
            var dir2 = Path.GetDirectoryName(path2);
            if (string.IsNullOrEmpty(dir1) || string.IsNullOrEmpty(dir2))
                return false;

            if (string.Equals(dir1, dir2, StringComparison.OrdinalIgnoreCase))
                return true;

            var parent1 = Directory.GetParent(dir1)?.FullName ?? dir1;
            var parent2 = Directory.GetParent(dir2)?.FullName ?? dir2;
            if (string.Equals(parent1, parent2, StringComparison.OrdinalIgnoreCase))
                return true;

            var grandParent1 = Directory.GetParent(parent1)?.FullName ?? parent1;
            var grandParent2 = Directory.GetParent(parent2)?.FullName ?? parent2;
            return string.Equals(grandParent1, grandParent2, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Executes the "Freeze & Prompt" algorithm:
    /// 1. Immediately freezes the source process via NtSuspendProcess.
    /// 2. Sends injection_prompt notification to GUI tray.
    /// 3. Awaits user decision with 60-second timeout.
    /// 4. If action is "kill" or timeout: terminates process. If "ignore": resumes process.
    /// </summary>
    public async Task ExecuteFreezeAndPromptAsync(int sourcePid, string sourcePath, int targetPid, string targetPath)
    {
        // 1. Freeze the process
        _logger.LogWarning("Freezing suspicious process PID {SourcePid} via NtSuspendProcess...", sourcePid);
        bool suspended = NtDllNative.SuspendProcess(sourcePid, out string? suspendError);
        if (!suspended)
        {
            // If the process has already exited, it was likely a short-lived launcher or transient child process
            _logger.LogInformation("Process PID {SourcePid} could not be suspended: {Error}. Skipping prompt.", sourcePid, suspendError);
            return;
        }

        _ipcServer.IncrementBlockedAttempts();
        _logger.LogInformation("Process PID {SourcePid} successfully frozen.", sourcePid);

        // 2. Dispatch prompt notification to GUI
        var prompt = new InjectionPromptNotification
        {
            PromptId = Guid.NewGuid().ToString(),
            SourcePid = sourcePid,
            SourcePath = sourcePath,
            TargetPid = targetPid,
            TargetPath = targetPath,
            Timestamp = DateTime.UtcNow,
            TimeoutSeconds = _config.PromptTimeoutSeconds
        };

        _logger.LogInformation("Dispatching prompt notification to GUI (PromptId: {PromptId}). Waiting up to {Seconds}s...",
            prompt.PromptId, _config.PromptTimeoutSeconds);

        string decision = await _ipcServer.PromptUserForInjectionDecisionAsync(
            prompt,
            TimeSpan.FromSeconds(_config.PromptTimeoutSeconds));

        _logger.LogInformation("Decision received for Prompt {PromptId}: '{Decision}'", prompt.PromptId, decision);

        // 3. Act on decision
        if (string.Equals(decision, "ignore", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation("User elected to IGNORE. Unfreezing process PID {SourcePid} via NtResumeProcess...", sourcePid);
            NtDllNative.ResumeProcess(sourcePid, out string? resumeError);
            if (resumeError != null)
                _logger.LogWarning("NtResumeProcess warning: {Error}", resumeError);
        }
        else
        {
            // Default or explicit "kill"
            _logger.LogWarning("Terminating suspicious process PID {SourcePid}...", sourcePid);
            bool killed = NtDllNative.KillProcess(sourcePid, out string? killError);
            if (killed)
                _logger.LogInformation("Process PID {SourcePid} successfully terminated.", sourcePid);
            else
                _logger.LogError("Failed to terminate process PID {SourcePid}: {Error}", sourcePid, killError);
        }
    }

    public void Stop()
    {
        _monitorCts?.Cancel();
        try
        {
            _etwSession?.Stop();
            _etwSession?.Dispose();
            _etwSession = null;
        }
        catch { }
    }

    public void Dispose()
    {
        Stop();
        _monitorCts?.Dispose();
    }
}
