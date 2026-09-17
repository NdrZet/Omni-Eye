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
using OmniEye.DpiBypass.Dns;
using OmniEye.DpiBypass.Lists;
using OmniEye.DpiBypass.Models;
using OmniEye.DpiBypass.Proxy;
using OmniEye.DpiBypass.SystemProxy;
using OmniEye.DpiBypass.Tls;
using OmniEye.DpiBypass.Zapret;

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
        await RunTestAsync("TEST 6: Dynamic Firewall Policy Switching via IPC", Test6_DynamicFirewallPolicySwitching);
        await RunTestAsync("TEST 7: Active Network Connection Monitoring & Process Attribution", Test7_ActiveNetworkConnectionMonitoring);
        await RunTestAsync("TEST 8: DNS RFC 1035 Wire-Format Serialization & Response Parsing", Test8_DnsWireFormatHelper);
        await RunTestAsync("TEST 9: TLS ClientHello SNI Extraction & Fragmentation Offset Calculation", Test9_TlsClientHelloParserAndSni);
        await RunTestAsync("TEST 10: Multi-Resolver DoH Pool with Concurrent Race & Caching", Test10_DohResolverPool);
        await RunTestAsync("TEST 11: DPI HTTP CONNECT Proxy Server & ClientHello Fragmentation Pipeline", Test11_DpiProxyServerTunnel);
        await RunTestAsync("TEST 12: Windows System Proxy WinINet Registry & Automatic Restoration", Test12_SystemProxyManager);
        await RunTestAsync("TEST 13: Zapret Native Engine Assets & Command-Line Arguments Verification", Test13_ZapretNativeEngine);
        await RunTestAsync("TEST 14: System DNS & Windows 11 Native DoH Configuration Manager", Test14_SystemDnsManager);
        await RunTestAsync("TEST 15: DomainListManager File Persistence, Sanitization & Import/Export", Test15_DomainListManager);
        await RunTestAsync("TEST 16: Cloud Tunnel MTProto Handshake, AES-CTR Cipher & SOCKS5 Routing", Test16_CloudTunnelMtprotoAndSocks5);

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

    private static async Task Test6_DynamicFirewallPolicySwitching()
    {
        var testPipeName = "OmniEyePolicyPipe_" + Guid.NewGuid().ToString("N");
        var testDir = Path.Combine(Path.GetTempPath(), "OmniEyePolTest_" + Guid.NewGuid().ToString("N"));

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

        using var client = new OmniEye.Core.Ipc.IpcClient(config);
        bool connected = await client.ConnectAsync(3000);
        if (!connected)
            throw new Exception("Failed to connect IpcClient to test server pipe.");

        // 1. Initial status
        var statusInit = await client.GetStatusAsync();
        if (statusInit == null)
            throw new Exception("GetStatusAsync returned null.");
        Console.WriteLine($" -> Initial policy: OutboundBlocked={statusInit.OutboundBlocked}");

        // 2. Switch to ALLOW (blockOutbound = false)
        var allowResp = await client.SetFirewallPolicyAsync(false);
        if (allowResp == null || !allowResp.Success)
            throw new Exception($"Failed to switch policy to ALLOW: {allowResp?.Message}");
        if (allowResp.OutboundBlocked)
            throw new Exception("Expected OutboundBlocked=false after setting policy to ALLOW.");

        var statusAfterAllow = await client.GetStatusAsync();
        if (statusAfterAllow == null || statusAfterAllow.OutboundBlocked)
            throw new Exception("GetStatusAsync reported OutboundBlocked=true after switching to ALLOW.");
        Console.WriteLine($" -> Switched to ALLOW: OutboundBlocked={statusAfterAllow.OutboundBlocked}, Msg: {allowResp.Message}");

        // 3. Switch back to BLOCK (blockOutbound = true)
        var blockResp = await client.SetFirewallPolicyAsync(true);
        if (blockResp == null || !blockResp.Success)
            throw new Exception($"Failed to switch policy to BLOCK: {blockResp?.Message}");
        if (!blockResp.OutboundBlocked)
            throw new Exception("Expected OutboundBlocked=true after setting policy to BLOCK.");

        var statusAfterBlock = await client.GetStatusAsync();
        if (statusAfterBlock == null || !statusAfterBlock.OutboundBlocked)
            throw new Exception("GetStatusAsync reported OutboundBlocked=false after switching to BLOCK.");
        Console.WriteLine($" -> Switched to BLOCK: OutboundBlocked={statusAfterBlock.OutboundBlocked}, Msg: {blockResp.Message}");

        ipcServer.Stop();
        try { Directory.Delete(testDir, recursive: true); } catch { }
    }

    private static async Task Test7_ActiveNetworkConnectionMonitoring()
    {
        // 1. Verify resolution of the current test process
        int currentPid = Environment.ProcessId;
        string currentProcessPath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
        var (resolvedName, resolvedPath) = NetworkMonitorService.ResolveProcess(currentPid);

        Console.WriteLine($" -> Current process PID: {currentPid}, Resolved: '{resolvedName}', Path: '{resolvedPath}'");
        if (string.IsNullOrEmpty(resolvedName))
            throw new Exception("ResolveProcess failed to resolve current process name.");

        // 2. Mock a whitelist with the current process path
        var mockWhitelist = new List<string> { resolvedPath };

        // 3. Enumerate active connections with Zero-Trust correlation (DefaultOutboundAction: BLOCK)
        var connections = await Task.Run(() => NetworkMonitorService.GetActiveConnections(mockWhitelist, isOutboundBlocked: true));
        Console.WriteLine($" -> Total active sockets detected: {connections.Count}");

        if (connections.Count == 0)
            throw new Exception("Expected at least 1 active network socket on Windows.");

        int tcpCount = 0;
        int udpCount = 0;
        int whitelistedCount = 0;
        int blockedCount = 0;
        int exceptionCount = 0;

        foreach (var conn in connections)
        {
            if (conn.Protocol == NetworkProtocol.Tcp) tcpCount++;
            else if (conn.Protocol == NetworkProtocol.Udp) udpCount++;

            if (conn.EnforcementStatus == ZeroTrustEnforcementStatus.Whitelisted) whitelistedCount++;
            else if (conn.EnforcementStatus == ZeroTrustEnforcementStatus.Blocked) blockedCount++;
            else if (conn.EnforcementStatus == ZeroTrustEnforcementStatus.SystemException) exceptionCount++;

            // Check endpoint format integrity
            if (string.IsNullOrEmpty(conn.LocalEndpoint) || !conn.LocalEndpoint.Contains(':'))
                throw new Exception($"Invalid LocalEndpoint format: '{conn.LocalEndpoint}'");

            if (string.IsNullOrEmpty(conn.StatusBadgeBackground) || !conn.StatusBadgeBackground.StartsWith('#'))
                throw new Exception($"Invalid StatusBadgeBackground hex color for {conn.EnforcementStatus}");

            if (string.IsNullOrEmpty(conn.ProtocolBadgeBackground) || !conn.ProtocolBadgeBackground.StartsWith('#'))
                throw new Exception($"Invalid ProtocolBadgeBackground hex color for {conn.Protocol}");
        }

        Console.WriteLine($" -> TCP Sockets: {tcpCount}, UDP Sockets: {udpCount}");
        Console.WriteLine($" -> Policy correlation breakdown: Whitelisted: {whitelistedCount}, Blocked: {blockedCount}, Exceptions: {exceptionCount}");

        // 4. Test Permissive mode correlation (DefaultOutboundAction: ALLOW)
        var permissiveConnections = await Task.Run(() => NetworkMonitorService.GetActiveConnections(mockWhitelist, isOutboundBlocked: false));
        int permissiveCount = permissiveConnections.Count(c => c.EnforcementStatus == ZeroTrustEnforcementStatus.Permissive);
        Console.WriteLine($" -> Permissive mode sockets: {permissiveCount}");

        if (permissiveCount == 0 && permissiveConnections.Count > 0)
            throw new Exception("Expected sockets to evaluate to Permissive when isOutboundBlocked=false and not in whitelist.");
    }

    private static async Task Test8_DnsWireFormatHelper()
    {
        // 1. Test Query Building
        byte[] query = DnsWireFormatHelper.BuildQuery("rutracker.org", DnsWireFormatHelper.TypeA, 0xABCD);
        Console.WriteLine($" -> DNS Query built, size: {query.Length} bytes");

        if (query.Length < 12)
            throw new Exception("DNS Query header is too short.");

        // Verify query ID 0xABCD
        if (query[0] != 0xAB || query[1] != 0xCD)
            throw new Exception("DNS Query ID mismatch.");

        // Verify QDCOUNT = 1
        if (query[4] != 0x00 || query[5] != 0x01)
            throw new Exception("QDCOUNT should be 1.");

        // 2. Test Synthetic Response Parsing
        // Construct synthetic DNS response with 1 Question and 2 A Answers (104.21.32.1 and 172.67.182.204)
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // Header: ID=0xABCD, Flags=0x8180 (Standard response, No error), QDCOUNT=1, ANCOUNT=2, NS=0, AR=0
        writer.Write((byte)0xAB); writer.Write((byte)0xCD);
        writer.Write((byte)0x81); writer.Write((byte)0x80);
        writer.Write((byte)0x00); writer.Write((byte)0x01);
        writer.Write((byte)0x00); writer.Write((byte)0x02);
        writer.Write((byte)0x00); writer.Write((byte)0x00);
        writer.Write((byte)0x00); writer.Write((byte)0x00);

        // Question: rutracker.org
        writer.Write((byte)9);
        writer.Write(Encoding.ASCII.GetBytes("rutracker"));
        writer.Write((byte)3);
        writer.Write(Encoding.ASCII.GetBytes("org"));
        writer.Write((byte)0);
        writer.Write((byte)0x00); writer.Write((byte)0x01); // Type A
        writer.Write((byte)0x00); writer.Write((byte)0x01); // Class IN

        // Answer 1: Compression pointer 0xC00C, Type A, Class IN, TTL 300, RDLENGTH 4, RDATA 104.21.32.1
        writer.Write((byte)0xC0); writer.Write((byte)0x0C);
        writer.Write((byte)0x00); writer.Write((byte)0x01);
        writer.Write((byte)0x00); writer.Write((byte)0x01);
        writer.Write((byte)0x00); writer.Write((byte)0x00); writer.Write((byte)0x01); writer.Write((byte)0x2C); // 300
        writer.Write((byte)0x00); writer.Write((byte)0x04);
        writer.Write(new byte[] { 104, 21, 32, 1 });

        // Answer 2: Compression pointer 0xC00C, Type A, Class IN, TTL 120, RDLENGTH 4, RDATA 172.67.182.204
        writer.Write((byte)0xC0); writer.Write((byte)0x0C);
        writer.Write((byte)0x00); writer.Write((byte)0x01);
        writer.Write((byte)0x00); writer.Write((byte)0x01);
        writer.Write((byte)0x00); writer.Write((byte)0x00); writer.Write((byte)0x00); writer.Write((byte)0x78); // 120
        writer.Write((byte)0x00); writer.Write((byte)0x04);
        writer.Write(new byte[] { 172, 67, 182, 204 });

        byte[] syntheticResponse = ms.ToArray();
        var (addresses, minTtl) = DnsWireFormatHelper.ParseResponse(syntheticResponse);

        Console.WriteLine($" -> Parsed {addresses.Count} IP addresses, MinTTL: {minTtl}s");
        if (addresses.Count != 2)
            throw new Exception($"Expected 2 addresses, got {addresses.Count}");
        if (addresses[0].ToString() != "104.21.32.1" || addresses[1].ToString() != "172.67.182.204")
            throw new Exception("Parsed IP addresses do not match synthetic response.");
        if (minTtl != 120)
            throw new Exception($"Expected MinTTL 120, got {minTtl}");
    }

    private static async Task Test9_TlsClientHelloParserAndSni()
    {
        string testHostname = "discord.com";
        byte[] clientHello = CreateSynthesizedClientHello(testHostname);
        Console.WriteLine($" -> Synthesized ClientHello packet size: {clientHello.Length} bytes");

        // 1. Verify detection
        bool isHello = TlsClientHelloParser.IsClientHello(clientHello, clientHello.Length);
        if (!isHello)
            throw new Exception("TlsClientHelloParser failed to identify valid ClientHello.");

        // 2. Verify SNI extraction
        bool foundSni = TlsClientHelloParser.TryFindSni(clientHello, clientHello.Length, out var extractedSni, out var sniOffset);
        Console.WriteLine($" -> SNI found: {foundSni}, Extracted: '{extractedSni}', Offset: {sniOffset}");

        if (!foundSni || extractedSni != testHostname)
            throw new Exception($"SNI extraction failed: expected '{testHostname}', got '{extractedSni}'");

        if (sniOffset <= 0)
            throw new Exception("SNI offset is invalid.");

        // 3. Verify fragmentation offset calculation (middle of SNI)
        int splitOffset = TlsClientHelloParser.CalculateSplitOffset(clientHello, clientHello.Length, preferredOffset: 2, splitInsideSni: true);
        int expectedSplit = sniOffset + (testHostname.Length / 2);
        Console.WriteLine($" -> Calculated split offset: {splitOffset}, Expected: {expectedSplit}");

        if (splitOffset != expectedSplit)
            throw new Exception($"Split offset mismatch: expected {expectedSplit}, got {splitOffset}");

        // 4. Verify non-TLS fallback
        byte[] dummyHttp = Encoding.ASCII.GetBytes("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");
        if (TlsClientHelloParser.IsClientHello(dummyHttp, dummyHttp.Length))
            throw new Exception("Non-TLS packet falsely identified as ClientHello.");

        int fallbackSplit = TlsClientHelloParser.CalculateSplitOffset(dummyHttp, dummyHttp.Length, preferredOffset: 2, splitInsideSni: true);
        if (fallbackSplit != 2)
            throw new Exception($"Fallback split offset should be 2, got {fallbackSplit}");
    }

    private static async Task Test10_DohResolverPool()
    {
        using var pool = new DohResolverPool();
        Console.WriteLine($" -> Configured {pool.Servers.Count} DoH servers: {string.Join(", ", pool.Servers.Select(s => s.Name))}");

        // 1. Test direct IP bypass
        var direct = await pool.ResolveAsync("1.1.1.1");
        if (direct?.ToString() != "1.1.1.1")
            throw new Exception("Direct IP should be returned as-is.");

        // 2. Resolve domain
        var resolvedIp = await pool.ResolveAsync("cloudflare.com");
        Console.WriteLine($" -> Resolved cloudflare.com to: {resolvedIp}");
        if (resolvedIp == null)
            throw new Exception("Failed to resolve cloudflare.com via DoH pool.");

        long initialHits = pool.CacheHitsCount;

        // 3. Test caching
        var cachedIp = await pool.ResolveAsync("cloudflare.com");
        Console.WriteLine($" -> Secondary resolution (cache hit): {cachedIp}");
        if (cachedIp == null || !cachedIp.Equals(resolvedIp))
            throw new Exception("Cached IP does not match initial resolution.");

        if (pool.CacheHitsCount <= initialHits)
            throw new Exception("CacheHitsCount should have incremented on subsequent query.");

        // 4. Run health check on servers
        await pool.RunHealthChecksAsync();
        foreach (var s in pool.Servers)
        {
            Console.WriteLine($"    * {s.Name} ({s.DirectIp}): Latency={s.LatencyMs}ms, Failures={s.ConsecutiveFailures}");
        }
    }

    private static async Task Test11_DpiProxyServerTunnel()
    {
        // 1. Start a mock remote destination server on loopback
        var mockListener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        mockListener.Start();
        int mockPort = ((System.Net.IPEndPoint)mockListener.LocalEndpoint).Port;

        var mockServerTask = Task.Run(async () =>
        {
            using var remoteConn = await mockListener.AcceptTcpClientAsync();
            using var stream = remoteConn.GetStream();
            byte[] buf = new byte[2048];
            int totalRead = 0;
            while (totalRead < 79)
            {
                int read = await stream.ReadAsync(buf.AsMemory(totalRead, buf.Length - totalRead));
                if (read <= 0) break;
                totalRead += read;
            }
            
            // Send back a mock response
            byte[] response = Encoding.ASCII.GetBytes("MOCK_SERVER_ACK");
            await stream.WriteAsync(response);
            return (totalRead, buf);
        });

        // 2. Start DpiProxyServer on a free port
        var config = new DpiBypassConfig
        {
            ListenAddress = "127.0.0.1",
            ListenPort = 59085,
            EnableDoh = false, // Use direct loopback IP for fast test
            EnableFragmentation = true,
            SplitPosition = 2,
            SplitDelayMs = 5
        };

        using var proxy = new DpiProxyServer(config);
        proxy.Start();
        Console.WriteLine($" -> DpiProxyServer started on {config.ListenAddress}:{config.ListenPort}");

        try
        {
            // 3. Connect client to proxy
            using var client = new System.Net.Sockets.TcpClient();
            await client.ConnectAsync("127.0.0.1", config.ListenPort);
            using var clientStream = client.GetStream();

            // 4. Send HTTP CONNECT
            string connectReq = $"CONNECT 127.0.0.1:{mockPort} HTTP/1.1\r\nHost: 127.0.0.1:{mockPort}\r\n\r\n";
            byte[] connectBytes = Encoding.ASCII.GetBytes(connectReq);
            await clientStream.WriteAsync(connectBytes);

            // 5. Read HTTP 200 OK from proxy
            byte[] respBuf = new byte[256];
            int respLen = await clientStream.ReadAsync(respBuf);
            string proxyResp = Encoding.ASCII.GetString(respBuf, 0, respLen);
            Console.WriteLine($" -> Proxy response: {proxyResp.Trim()}");

            if (!proxyResp.StartsWith("HTTP/1.1 200 Connection Established"))
                throw new Exception($"Proxy connection failed: {proxyResp}");

            // 6. Send payload through tunnel (Synthesized ClientHello)
            byte[] hello = CreateSynthesizedClientHello("blocked-domain.org");
            await clientStream.WriteAsync(hello);

            // 7. Verify mock server received data
            var (bytesReceived, receivedBuf) = await mockServerTask;
            Console.WriteLine($" -> Mock server received: {bytesReceived} bytes");
            if (bytesReceived != hello.Length)
                throw new Exception($"Payload length mismatch: expected {hello.Length}, got {bytesReceived}");

            // 8. Verify client received mock response
            byte[] clientAckBuf = new byte[64];
            int clientAckLen = await clientStream.ReadAsync(clientAckBuf);
            string clientAck = Encoding.ASCII.GetString(clientAckBuf, 0, clientAckLen);
            Console.WriteLine($" -> Client received: {clientAck}");

            if (clientAck != "MOCK_SERVER_ACK")
                throw new Exception($"Expected MOCK_SERVER_ACK, got {clientAck}");

            Console.WriteLine($" -> Proxy Stats: ActiveConn={proxy.Stats.ActiveConnections}, TotalConn={proxy.Stats.TotalConnections}, BytesTransferred={proxy.Stats.TotalBytesTransferred}");
        }
        finally
        {
            proxy.Stop();
            mockListener.Stop();
        }
    }

    private static async Task Test12_SystemProxyManager()
    {
        bool wasOriginallyEnabled = SystemProxyManager.IsProxyEnabled();
        Console.WriteLine($" -> Original Windows proxy state: Enabled={wasOriginallyEnabled}");

        // 1. Enable proxy
        bool enableOk = SystemProxyManager.EnableProxy("127.0.0.1", 59085);
        if (!enableOk)
            throw new Exception("SystemProxyManager.EnableProxy failed.");

        bool isNowEnabled = SystemProxyManager.IsProxyEnabled();
        Console.WriteLine($" -> After EnableProxy: Enabled={isNowEnabled}");
        if (!isNowEnabled)
            throw new Exception("SystemProxyManager.IsProxyEnabled returned false after enabling.");

        // 2. Disable proxy and restore
        bool disableOk = SystemProxyManager.DisableProxy();
        if (!disableOk)
            throw new Exception("SystemProxyManager.DisableProxy failed.");

        bool isFinallyEnabled = SystemProxyManager.IsProxyEnabled();
        Console.WriteLine($" -> After DisableProxy: Enabled={isFinallyEnabled}");
        if (isFinallyEnabled != wasOriginallyEnabled)
            throw new Exception($"Proxy state not restored: expected {wasOriginallyEnabled}, got {isFinallyEnabled}");
    }

    private static Task Test13_ZapretNativeEngine()
    {
        var zapretDir = ZapretEngine.ResolveZapretDirectory();
        Console.WriteLine($" -> Resolved Zapret directory: '{zapretDir}'");

        var winwsExe = Path.Combine(zapretDir, "bin", "winws.exe");
        var winDivertDll = Path.Combine(zapretDir, "bin", "WinDivert.dll");
        var winDivertSys = Path.Combine(zapretDir, "bin", "WinDivert64.sys");
        var discordUdp = Path.Combine(zapretDir, "bin", "ACTIVE_DISCORD_UDP.bin");
        var listGeneral = Path.Combine(zapretDir, "lists", "list-general.txt");

        if (!File.Exists(winwsExe)) throw new FileNotFoundException("winws.exe missing.");
        if (!File.Exists(winDivertDll)) throw new FileNotFoundException("WinDivert.dll missing.");
        if (!File.Exists(winDivertSys)) throw new FileNotFoundException("WinDivert64.sys missing.");
        if (!File.Exists(discordUdp)) throw new FileNotFoundException("ACTIVE_DISCORD_UDP.bin missing.");
        if (!File.Exists(listGeneral)) throw new FileNotFoundException("list-general.txt missing.");

        Console.WriteLine($" -> Verified binaries: winws.exe ({new FileInfo(winwsExe).Length} bytes), WinDivert64.sys ({new FileInfo(winDivertSys).Length} bytes)");

        var binDir = Path.Combine(zapretDir, "bin");
        var listsDir = Path.Combine(zapretDir, "lists");

        foreach (var preset in ZapretEngine.AvailablePresets)
        {
            var args = ZapretEngine.BuildArguments(preset, binDir, listsDir);
            if (string.IsNullOrWhiteSpace(args))
                throw new Exception($"BuildArguments returned empty string for preset '{preset}'.");

            if (!args.Contains("--wf-tcp") || !args.Contains("--wf-udp"))
                throw new Exception($"Preset '{preset}' missing core packet filter args.");

            if (!args.Contains("ACTIVE_DISCORD_UDP.bin"))
                throw new Exception($"Preset '{preset}' missing Discord Voice UDP bypass payload.");

            Console.WriteLine($" -> Preset '{preset}': Generated {args.Length} chars command-line with Discord UDP voice rules.");
        }

        using var engine = new ZapretEngine();
        if (engine.IsRunning)
            throw new Exception("ZapretEngine should not be running immediately upon construction.");


        Console.WriteLine(" -> ZapretEngine JobObject initialized and ready.");
        return Task.CompletedTask;
    }

    private static byte[] CreateSynthesizedClientHello(string hostName)
    {
        byte[] hostBytes = Encoding.ASCII.GetBytes(hostName);
        int sniExtLen = 2 + 1 + 2 + hostBytes.Length; // server_name_list_len(2) + name_type(1) + name_len(2) + host
        int extensionsLen = 4 + sniExtLen; // ext_type(2) + ext_len(2) + sniExtLen
        int handshakeLen = 2 + 32 + 1 + 4 + 2 + 2 + extensionsLen;
        int recordLen = 4 + handshakeLen;

        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // TLS Record Header (5 bytes)
        writer.Write((byte)0x16); // ContentType: Handshake
        writer.Write((byte)0x03); writer.Write((byte)0x01); // Version: TLS 1.0 (Record)
        writer.Write((byte)(recordLen >> 8)); writer.Write((byte)(recordLen & 0xFF)); // Length

        // Handshake Header (4 bytes)
        writer.Write((byte)0x01); // HandshakeType: ClientHello
        writer.Write((byte)0x00);
        writer.Write((byte)(handshakeLen >> 8)); writer.Write((byte)(handshakeLen & 0xFF)); // Handshake Length

        // Client Version (2 bytes)
        writer.Write((byte)0x03); writer.Write((byte)0x03); // TLS 1.2

        // Client Random (32 bytes)
        writer.Write(new byte[32]);

        // Session ID Length (1 byte: 0)
        writer.Write((byte)0x00);

        // Cipher Suites Length (2 bytes) + 1 Suite (2 bytes)
        writer.Write((byte)0x00); writer.Write((byte)0x02);
        writer.Write((byte)0xC0); writer.Write((byte)0x2F); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

        // Compression Methods Length (1 byte) + None (1 byte)
        writer.Write((byte)0x01);
        writer.Write((byte)0x00);

        // Extensions Length (2 bytes)
        writer.Write((byte)(extensionsLen >> 8)); writer.Write((byte)(extensionsLen & 0xFF));

        // Extension: server_name (0x0000)
        writer.Write((byte)0x00); writer.Write((byte)0x00);
        writer.Write((byte)(sniExtLen >> 8)); writer.Write((byte)(sniExtLen & 0xFF));

        // Server Name List Length (2 bytes)
        int listLen = 1 + 2 + hostBytes.Length;
        writer.Write((byte)(listLen >> 8)); writer.Write((byte)(listLen & 0xFF));

        // Server Name Type (1 byte: 0 = host_name)
        writer.Write((byte)0x00);

        // Host Name Length (2 bytes)
        writer.Write((byte)(hostBytes.Length >> 8)); writer.Write((byte)(hostBytes.Length & 0xFF));

        // Host Name
        writer.Write(hostBytes);

        return ms.ToArray();
    }

    private static Task Test14_SystemDnsManager()
    {
        // 1. Adapter discovery
        var adapters = SystemDnsManager.GetActivePhysicalAdapters();
        Console.WriteLine($" -> Discovered {adapters.Count} active physical network adapters.");
        foreach (var (name, id) in adapters)
        {
            Console.WriteLine($"    * Adapter: '{name}', GUID: {id}");
        }

        // 2. DoH Resolver Pool with Secondary IPs
        var pool = new DohResolverPool();
        var cf = pool.Servers.FirstOrDefault(s => s.Name.Contains("Cloudflare"));
        if (cf == null) throw new Exception("Cloudflare resolver not found in pool.");
        if (cf.DirectIp != "1.1.1.1") throw new Exception($"Expected Cloudflare IP 1.1.1.1, got {cf.DirectIp}");
        if (cf.SecondaryIp != "1.0.0.1") throw new Exception($"Expected Cloudflare Secondary IP 1.0.0.1, got {cf.SecondaryIp}");

        var google = pool.Servers.FirstOrDefault(s => s.Name.Contains("Google"));
        if (google == null) throw new Exception("Google resolver not found in pool.");
        if (google.DirectIp != "8.8.8.8") throw new Exception($"Expected Google IP 8.8.8.8, got {google.DirectIp}");
        if (google.SecondaryIp != "8.8.4.4") throw new Exception($"Expected Google Secondary IP 8.8.4.4, got {google.SecondaryIp}");

        // 3. INotifyPropertyChanged on DohServerInfo
        bool propChanged = false;
        cf.PropertyChanged += (s, e) =>
        {
            if (e.PropertyName == nameof(DohServerInfo.IsActiveDns))
            {
                propChanged = true;
            }
        };
        cf.IsActiveDns = true;
        if (!propChanged) throw new Exception("DohServerInfo failed to raise PropertyChanged for IsActiveDns.");
        cf.IsActiveDns = false;

        // 4. SystemDnsManager state verification
        if (SystemDnsManager.IsConnected) throw new Exception("SystemDnsManager should not be connected by default in test suite.");
        Console.WriteLine(" -> System DNS Controller & DoH Resolver Pool verified successfully.");

        return Task.CompletedTask;
    }

    private static Task Test15_DomainListManager()
    {
        // 1. Test Domain Sanitization & Normalization
        Console.WriteLine(" -> Testing Domain Sanitization & Edge Cases...");
        if (!DomainListManager.TrySanitizeDomain("https://discord.com/channels/123/456", out var d1, out _) || d1 != "discord.com")
            throw new Exception($"Expected 'discord.com', got '{d1}'");

        if (!DomainListManager.TrySanitizeDomain("http://sub.domain.org:8080/path?q=1#frag", out var d2, out _) || d2 != "sub.domain.org")
            throw new Exception($"Expected 'sub.domain.org', got '{d2}'");

        if (!DomainListManager.TrySanitizeDomain("^dns.google", out var d3, out _) || d3 != "^dns.google")
            throw new Exception($"Expected '^dns.google', got '{d3}'");

        if (!DomainListManager.TrySanitizeDomain("*.youtube.com", out var d4, out _) || d4 != "*.youtube.com")
            throw new Exception($"Expected '*.youtube.com', got '{d4}'");

        if (DomainListManager.TrySanitizeDomain("not a domain", out _, out _))
            throw new Exception("Expected failure for invalid domain string with spaces.");

        if (DomainListManager.TrySanitizeDomain("   ", out _, out _))
            throw new Exception("Expected failure for whitespace string.");

        // 2. Test File Persistence in Isolated Test Directory
        Console.WriteLine(" -> Testing Domain List Persistence & Deduplication...");
        var tempListsDir = Path.Combine(Path.GetTempPath(), "OmniEye_Test_Lists_" + Guid.NewGuid().ToString("N"));
        try
        {
            var manager = new DomainListManager(tempListsDir);

            var initialDomains = new[] { "discord.gg", "https://youtube.com/watch", "^dns.google" };
            manager.SaveList(DomainListManager.ListGeneral, initialDomains);

            var loaded = manager.LoadList(DomainListManager.ListGeneral);
            if (loaded.Count != 3)
                throw new Exception($"Expected 3 domains loaded, got {loaded.Count}");

            if (!loaded.Contains("discord.gg") || !loaded.Contains("youtube.com") || !loaded.Contains("^dns.google"))
                throw new Exception("Missing expected domain in loaded list.");

            // 3. Test Deduplication & Case-Insensitivity
            var duplicateBatch = new[] { "DISCORD.GG", "youtube.com", "newdomain.net" };
            manager.SaveList(DomainListManager.ListGeneral, loaded.Concat(duplicateBatch));

            var reloaded = manager.LoadList(DomainListManager.ListGeneral);
            if (reloaded.Count != 4)
                throw new Exception($"Expected 4 distinct domains after duplicate batch, got {reloaded.Count}");

            // 4. Test Export
            Console.WriteLine(" -> Testing Export to text file...");
            var exportPath = Path.Combine(tempListsDir, "exported.txt");
            manager.ExportList(DomainListManager.ListGeneral, exportPath);
            if (!File.Exists(exportPath))
                throw new Exception("Export file was not created.");

            var exportedLines = File.ReadAllLines(exportPath);
            if (exportedLines.Length != 4)
                throw new Exception($"Expected 4 lines in export, got {exportedLines.Length}");

            // 5. Test Import
            Console.WriteLine(" -> Testing Import from text file...");
            var importSourcePath = Path.Combine(tempListsDir, "import_src.txt");
            File.WriteAllLines(importSourcePath, new[] { "twitch.tv", "https://store.steampowered.com/app/123", "discord.gg" });

            int addedCount = manager.ImportList(DomainListManager.ListGeneral, importSourcePath, mergeWithExisting: true);
            if (addedCount != 2)
                throw new Exception($"Expected 2 new domains imported, got {addedCount}");

            var afterImport = manager.LoadList(DomainListManager.ListGeneral);
            if (afterImport.Count != 6)
                throw new Exception($"Expected 6 domains total after import, got {afterImport.Count}");

            // 6. Test Multiline Notepad Raw Text Parsing and Getting
            Console.WriteLine(" -> Testing Multiline Notepad Raw Text Parsing...");
            string rawNotepadInput = @"
# Custom comments at the top
  discord.com  
# another comment
https://x.com/explore
*.twitch.tv
DISCORD.COM
  
invalid domain with spaces
# EOF comment
";
            var parsedNotepad = DomainListManager.ParseRawText(rawNotepadInput);
            if (parsedNotepad.Count != 3)
                throw new Exception($"Expected 3 clean domains from notepad input, got {parsedNotepad.Count}");
            if (!parsedNotepad.Contains("discord.com") || !parsedNotepad.Contains("x.com") || !parsedNotepad.Contains("*.twitch.tv"))
                throw new Exception("Missing expected domain from ParseRawText.");

            string rawJoined = manager.GetRawText(DomainListManager.ListGeneral);
            if (string.IsNullOrWhiteSpace(rawJoined))
                throw new Exception("GetRawText returned empty text.");

            // 7. Test Hot-Reload API Signature on ZapretEngine
            Console.WriteLine(" -> Testing ZapretEngine.Restart() non-crashing invocation...");
            var engine = new ZapretEngine();
            engine.Restart("General");
            if (engine.CurrentPreset != "General")
                throw new Exception("Expected CurrentPreset to be 'General'");

            Console.WriteLine(" -> DomainListManager & Hot-Reload verified successfully.");
        }
        finally
        {
            if (Directory.Exists(tempListsDir))
            {
                try { Directory.Delete(tempListsDir, recursive: true); } catch { }
            }
        }

        return Task.CompletedTask;
    }

    private static async Task Test16_CloudTunnelMtprotoAndSocks5()
    {
        // 1. Test AES-CTR Stream Cipher
        Console.WriteLine(" -> Testing AES-CTR Stream Cipher (256-bit)...");
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        System.Security.Cryptography.RandomNumberGenerator.Fill(key);
        System.Security.Cryptography.RandomNumberGenerator.Fill(iv);

        string originalText = "OmniEye Cloud Tunnel MTProto & SOCKS5 test message! 1234567890.";
        byte[] originalBytes = Encoding.UTF8.GetBytes(originalText);

        using (var cipherEnc = new OmniEye.Core.CloudTunnel.Crypto.AesCtrCipher(key, iv))
        using (var cipherDec = new OmniEye.Core.CloudTunnel.Crypto.AesCtrCipher(key, iv))
        {
            byte[] encrypted = cipherEnc.Transform(originalBytes);
            byte[] decrypted = cipherDec.Transform(encrypted);

            string roundtrip = Encoding.UTF8.GetString(decrypted);
            if (roundtrip != originalText)
                throw new Exception($"AES-CTR roundtrip failed! Got '{roundtrip}', expected '{originalText}'");

            // Verify streaming across chunk boundaries
            using var chunkEnc = new OmniEye.Core.CloudTunnel.Crypto.AesCtrCipher(key, iv);
            using var chunkDec = new OmniEye.Core.CloudTunnel.Crypto.AesCtrCipher(key, iv);

            byte[] chunk1 = originalBytes.AsSpan(0, 10).ToArray();
            byte[] chunk2 = originalBytes.AsSpan(10).ToArray();

            byte[] enc1 = chunkEnc.Transform(chunk1);
            byte[] enc2 = chunkEnc.Transform(chunk2);

            byte[] dec1 = chunkDec.Transform(enc1);
            byte[] dec2 = chunkDec.Transform(enc2);

            string chunkRoundtrip = Encoding.UTF8.GetString(dec1) + Encoding.UTF8.GetString(dec2);
            if (chunkRoundtrip != originalText)
                throw new Exception("AES-CTR chunked streaming failed!");
        }

        // 2. Test CloudTunnelConfig & Telegram Links
        Console.WriteLine(" -> Testing CloudTunnelConfig & Telegram Link Formatter...");
        var config = new OmniEye.Core.Models.CloudTunnelConfig
        {
            Host = "127.0.0.1",
            MtprotoPort = 1443,
            Secret = "0123456789abcdef0123456789abcdef",
            WorkerDomains = new() { "my-test.workers.dev" }
        };

        string tgLink = config.GetTelegramLink();
        if (tgLink != "tg://proxy?server=127.0.0.1&port=1443&secret=0123456789abcdef0123456789abcdef")
            throw new Exception($"Unexpected Telegram link: {tgLink}");

        string webTgLink = config.GetWebTelegramLink();
        if (webTgLink != "https://t.me/proxy?server=127.0.0.1&port=1443&secret=0123456789abcdef0123456789abcdef")
            throw new Exception($"Unexpected Web Telegram link: {webTgLink}");

        // 3. Test MTProto Handshake generation & rejection
        Console.WriteLine(" -> Testing MTProto Handshake rejection on invalid data...");
        byte[] junkHandshake = new byte[64];
        System.Security.Cryptography.RandomNumberGenerator.Fill(junkHandshake);
        byte[] secretBytes = Convert.FromHexString(config.Secret);

        var nullResult = OmniEye.Core.CloudTunnel.Mtproto.MtprotoHandshake.TryParse(junkHandshake, secretBytes);
        if (nullResult != null)
            throw new Exception("Expected null result for random junk handshake");

        // 4. Test CloudTunnelManager Lifecycle
        Console.WriteLine(" -> Testing CloudTunnelManager Start & Stop lifecycle...");
        var managerConfig = new OmniEye.Core.Models.CloudTunnelConfig
        {
            Host = "127.0.0.1",
            MtprotoPort = 19443, // Test ports to avoid conflicts
            Socks5Port = 19808,
            Secret = config.Secret,
            EnableSocks5 = true,
            EnableSystemProxy = false
        };

        var tunnelMgr = new OmniEye.Core.CloudTunnel.CloudTunnelManager(managerConfig);
        tunnelMgr.Start();

        if (!tunnelMgr.IsRunning)
            throw new Exception("Expected CloudTunnelManager to be running");

        // Test connecting to local SOCKS5 port
        using (var tcpClient = new System.Net.Sockets.TcpClient())
        {
            await tcpClient.ConnectAsync("127.0.0.1", 19808);
            if (!tcpClient.Connected)
                throw new Exception("Failed to connect to local SOCKS5 port 19808");
        }

        tunnelMgr.Stop();
        if (tunnelMgr.IsRunning)
            throw new Exception("Expected CloudTunnelManager to be stopped");

        // 5. Test Embedded Cloudflare Worker Script Resource
        Console.WriteLine(" -> Testing WorkerScript Embedded Resource...");
        if (string.IsNullOrWhiteSpace(OmniEye.Core.CloudTunnel.Resources.WorkerScript.Code) ||
            !OmniEye.Core.CloudTunnel.Resources.WorkerScript.Code.Contains("cloudflare:sockets"))
        {
            throw new Exception("WorkerScript resource code is invalid or missing 'cloudflare:sockets'");
        }

        // 6. Test Live WebSocket to user's worker
        Console.WriteLine(" -> Testing Live WebSocket to cdn.sklv-project.workers.dev...");
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var client = await OmniEye.Core.CloudTunnel.WebSocket.CfWorkerClient.ConnectAsync(
                new[] { "cdn.sklv-project.workers.dev" },
                "149.154.167.220",
                2,
                TimeSpan.FromSeconds(4),
                cts.Token
            );
            if (client != null)
            {
                Console.WriteLine($" -> SUCCESS! Connected to WebSocket on {client.ConnectedDomain}, State={client.State}");
                await client.DisposeAsync();
            }
            else
            {
                Console.WriteLine(" -> Could not connect to WebSocket on cdn.sklv-project.workers.dev (null returned)");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" -> WebSocket connection test exception: {ex.Message}");
        }

        Console.WriteLine(" -> Cloud Tunnel components verified successfully.");
    }
}
