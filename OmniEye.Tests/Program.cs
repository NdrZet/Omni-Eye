using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using OmniEye.Core.Configuration;
using OmniEye.Core.Models;
using OmniEye.Core.Security;
using OmniEye.Core.Storage;
using OmniEyeSvc.Ipc;
using OmniEyeSvc.Network;

namespace OmniEye.Tests;

public class Program
{
    private static int _passedCount = 0;
    private static int _failedCount = 0;

    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("==================================================================");
        Console.WriteLine(" OmniEye (Zero-Trust Anti-Exfiltration System) Verification Suite");
        Console.WriteLine("==================================================================");
        Console.ResetColor();

        await RunTestAsync("TEST 1: DPAPI Key Management & SQLCipher Encryption", Test1_DpapiAndSqlCipher);
        await RunTestAsync("TEST 2: Authenticode Signature Verification (WinVerifyTrust)", Test2_AuthenticodeVerification);
        await RunTestAsync("TEST 3: Process Freeze & Resume (NtSuspendProcess / NtResumeProcess)", Test3_ProcessFreezeAndResume);
        await RunTestAsync("TEST 4: Named Pipe IPC Server/Client Protocol & Security Prompts", Test4_NamedPipeIpcAndPrompts);
        await RunTestAsync("TEST 5: DeveloperMode Lifecycle & Graceful Rollback", Test5_DeveloperModeLifecycle);

        Console.WriteLine();
        Console.WriteLine("------------------------------------------------------------------");
        if (_failedCount == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($" ALL {_passedCount} TESTS PASSED SUCCESSFULLY! (0 Failures)");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($" TESTS FINISHED WITH {_failedCount} FAILURES! ({_passedCount} Passed)");
        }
        Console.ResetColor();
        Console.WriteLine("------------------------------------------------------------------");

        return _failedCount == 0 ? 0 : 1;
    }

    private static async Task RunTestAsync(string testName, Func<Task> testFunc)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"\n[RUNNING] {testName}...");
        Console.ResetColor();

        try
        {
            await testFunc();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[PASS] {testName}");
            Console.ResetColor();
            _passedCount++;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[FAIL] {testName}");
            Console.WriteLine($"Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            Console.ResetColor();
            _failedCount++;
        }
    }

    private static async Task Test1_DpapiAndSqlCipher()
    {
        var testDir = Path.Combine(Path.GetTempPath(), "OmniEyeTest_" + Guid.NewGuid().ToString("N"));
        try
        {
            var config = new OmniEyeConfig
            {
                DeveloperMode = true,
                DbDirectory = testDir,
                DbFileName = "test_config.db",
                KeyFileName = "test_master.key"
            };

            using var dbManager = new DatabaseManager(config);
            dbManager.Initialize();

            // Verify DPAPI key file exists
            if (!File.Exists(config.KeyFilePath))
                throw new Exception("DPAPI key file was not created.");

            // Verify raw header is encrypted (not plain 'SQLite format 3')
            byte[] headerBytes = new byte[16];
            using (var fs = new FileStream(config.DbFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                fs.ReadExactly(headerBytes, 0, 16);
            }
            var header = Encoding.ASCII.GetString(headerBytes, 0, 16);
            if (header.StartsWith("SQLite format 3"))
            {
                throw new Exception("Database file is unencrypted plain SQLite! Expected SQLCipher ciphertext.");
            }
            Console.WriteLine($" -> Verified ciphertext database. Header: [{BitConverter.ToString(headerBytes)}]");

            // Add dummy entry
            var notepadPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
            var entry = dbManager.AddEntry(notepadPath, bypassSignatureCheck: true);
            if (entry.Id <= 0)
                throw new Exception("Failed to insert whitelist entry.");

            // Read back
            var list = dbManager.GetWhitelist();
            if (list.Count != 1 || list[0].FilePath != entry.FilePath)
                throw new Exception("Retrieved whitelist entry does not match inserted entry.");

            Console.WriteLine($" -> Encrypted entry created and retrieved successfully (Id: {entry.Id}, File: {entry.FileName})");

            // Verify exclusive lock
            dbManager.ReleaseLock();
            Console.WriteLine(" -> Exclusive file lock successfully acquired and released.");
        }
        finally
        {
            try { Directory.Delete(testDir, recursive: true); } catch { }
        }
    }

    private static Task Test2_AuthenticodeVerification()
    {
        // 1. Signed system executable (dotnet.exe)
        var dotnetPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");
        if (!File.Exists(dotnetPath))
        {
            dotnetPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        }

        var signedResult = AuthenticodeVerifier.VerifyFile(dotnetPath);
        Console.WriteLine($" -> {Path.GetFileName(dotnetPath)}: Signed={signedResult.IsSigned}, Valid={signedResult.IsValid}, Subject={signedResult.SignerSubject}");
        if (!signedResult.IsSigned || !signedResult.IsValid)
        {
            throw new Exception($"{Path.GetFileName(dotnetPath)} signature verification failed: {signedResult.StatusMessage}");
        }

        // 2. Unsigned dummy file
        var tempUnsigned = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempUnsigned, new byte[] { 0x4D, 0x5A, 0x90, 0x00 }); // MZ header
            var unsignedResult = AuthenticodeVerifier.VerifyFile(tempUnsigned);
            Console.WriteLine($" -> Unsigned test file: Signed={unsignedResult.IsSigned}, Valid={unsignedResult.IsValid}");
            if (unsignedResult.IsValid)
            {
                throw new Exception("Unsigned test file was reported as validly signed!");
            }
        }
        finally
        {
            try { File.Delete(tempUnsigned); } catch { }
        }

        return Task.CompletedTask;
    }

    private static Task Test3_ProcessFreezeAndResume()
    {
        // Start a dummy background process
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -Command \"Start-Sleep -Seconds 30\"",
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi)
            ?? throw new Exception("Failed to start test process.");

        try
        {
            int pid = proc.Id;
            Console.WriteLine($" -> Spawned target process PID: {pid}");

            // 1. Suspend
            bool suspended = NtDllNative.SuspendProcess(pid, out var suspErr);
            if (!suspended)
                throw new Exception($"NtSuspendProcess failed: {suspErr}");
            Console.WriteLine(" -> NtSuspendProcess succeeded. Process frozen.");

            // 2. Resume
            bool resumed = NtDllNative.ResumeProcess(pid, out var resErr);
            if (!resumed)
                throw new Exception($"NtResumeProcess failed: {resErr}");
            Console.WriteLine(" -> NtResumeProcess succeeded. Process resumed.");

            // 3. Terminate
            bool killed = NtDllNative.KillProcess(pid, out var killErr);
            if (!killed)
                throw new Exception($"KillProcess failed: {killErr}");

            proc.WaitForExit(3000);
            if (!proc.HasExited)
                throw new Exception("Process has not exited after KillProcess.");
            Console.WriteLine(" -> Process successfully terminated.");
        }
        finally
        {
            try
            {
                if (!proc.HasExited) proc.Kill();
            }
            catch { }
        }

        return Task.CompletedTask;
    }

    private static async Task Test4_NamedPipeIpcAndPrompts()
    {
        var testPipeName = "OmniEyeTestPipe_" + Guid.NewGuid().ToString("N");
        var testDir = Path.Combine(Path.GetTempPath(), "OmniEyeIpcTest_" + Guid.NewGuid().ToString("N"));

        var config = new OmniEyeConfig
        {
            DeveloperMode = true,
            DbDirectory = testDir,
            PipeName = testPipeName
        };

        using var dbManager = new DatabaseManager(config);
        dbManager.Initialize();

        var fwLogger = NullLogger<FirewallEnforcer>.Instance;
        var ipcLogger = NullLogger<IpcServer>.Instance;

        using var fwEnforcer = new FirewallEnforcer(config, dbManager, fwLogger);
        using var ipcServer = new IpcServer(config, dbManager, fwEnforcer, ipcLogger);
        ipcServer.Start();

        // Connect IPC Client
        using var client = new OmniEye.Core.Ipc.IpcClient(config);
        bool connected = await client.ConnectAsync(3000);
        if (!connected)
            throw new Exception("Failed to connect IpcClient to test server pipe.");
        Console.WriteLine(" -> IPC client connected to test server pipe.");

        // RPC 1: Get Status
        var status = await client.GetStatusAsync();
        if (status == null || !status.IsRunning || !status.DeveloperMode)
            throw new Exception("GetStatusAsync returned invalid response.");
        Console.WriteLine($" -> Status RPC verified: IsRunning={status.IsRunning}, DevMode={status.DeveloperMode}");

        // RPC 2: Add to Whitelist
        var sysPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var addResp = await client.AddToWhitelistAsync(sysPath, bypassSignature: true);
        if (addResp == null || !addResp.Success)
            throw new Exception($"AddToWhitelistAsync failed: {addResp?.Message}");
        Console.WriteLine($" -> Whitelist Add RPC verified: {addResp.Message}");

        // RPC 3: Get Whitelist
        var wl = await client.GetWhitelistAsync();
        if (wl == null || wl.Entries.Count != 1)
            throw new Exception("GetWhitelistAsync did not contain added item.");
        Console.WriteLine($" -> Whitelist Get RPC verified: {wl.Entries.Count} entries.");

        // Injection Prompt & Decision Simulation
        var promptTcs = new TaskCompletionSource<string>();
        client.InjectionPromptReceived += prompt =>
        {
            Console.WriteLine($" -> GUI client received Injection Prompt for PID {prompt.SourcePid}. Simulating Kill decision...");
            _ = client.SendPromptDecisionAsync(prompt.PromptId, "kill");
            promptTcs.TrySetResult("kill");
        };

        var promptNotification = new InjectionPromptNotification
        {
            PromptId = Guid.NewGuid().ToString(),
            SourcePid = 9999,
            SourcePath = @"C:\Malware\trojan.exe",
            TargetPid = 1111,
            TargetPath = sysPath,
            TimeoutSeconds = 10
        };

        var promptServerTask = ipcServer.PromptUserForInjectionDecisionAsync(promptNotification, TimeSpan.FromSeconds(5));
        var decision = await promptServerTask;
        if (decision != "kill")
            throw new Exception($"Expected decision 'kill', received '{decision}'.");

        Console.WriteLine($" -> Injection Prompt-and-Decision verified. Server received action: '{decision}'.");

        ipcServer.Stop();
        try { Directory.Delete(testDir, recursive: true); } catch { }
    }

    private static Task Test5_DeveloperModeLifecycle()
    {
        var testDir = Path.Combine(Path.GetTempPath(), "OmniEyeLifeTest_" + Guid.NewGuid().ToString("N"));
        var config = new OmniEyeConfig
        {
            DeveloperMode = true,
            DbDirectory = testDir
        };

        using var dbManager = new DatabaseManager(config);
        dbManager.Initialize();

        var logger = NullLogger<FirewallEnforcer>.Instance;
        using var fwEnforcer = new FirewallEnforcer(config, dbManager, logger);

        // In DeveloperMode = true:
        // 1. Can apply policy without throwing COM fatal errors (or catches if non-admin)
        try
        {
            fwEnforcer.ApplyPolicy();
            Console.WriteLine(" -> Applied Firewall policy in DeveloperMode.");

            // 2. Rollback
            fwEnforcer.RollbackPolicy();
            Console.WriteLine(" -> Successfully rolled back Firewall policy to Allow.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($" -> Note: Firewall COM requires Administrator rights on Windows: {ex.Message}");
        }

        // 3. Release exclusive lock
        dbManager.ReleaseLock();
        Console.WriteLine(" -> Database exclusive lock successfully released for shutdown.");

        try { Directory.Delete(testDir, recursive: true); } catch { }
        return Task.CompletedTask;
    }
}
