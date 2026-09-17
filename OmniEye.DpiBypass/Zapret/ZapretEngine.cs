using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace OmniEye.DpiBypass.Zapret;

/// <summary>
/// Native process runner for Zapret (winws.exe + WinDivert) with Windows JobObject binding
/// for guaranteed termination and driver unloading on application exit.
/// </summary>
public class ZapretEngine : IDisposable
{
    private Process? _process;
    private bool _usedShellExecute = false;
    private IntPtr _jobHandle = IntPtr.Zero;
    private readonly object _lock = new();

    public bool IsRunning
    {
        get
        {
            lock (_lock)
            {
                if (_process == null) return false;
                try
                {
                    if (!_process.HasExited) return true;
                }
                catch { }

                if (_usedShellExecute)
                {
                    try
                    {
                        var procs = Process.GetProcessesByName("winws");
                        bool any = procs.Length > 0;
                        foreach (var p in procs) p.Dispose();
                        return any;
                    }
                    catch { }
                }

                return false;
            }
        }
    }

    public int? ProcessId
    {
        get
        {
            lock (_lock)
            {
                if (_process == null) return null;
                try
                {
                    if (!_process.HasExited) return _process.Id;
                }
                catch { }

                if (_usedShellExecute)
                {
                    try
                    {
                        var procs = Process.GetProcessesByName("winws");
                        if (procs.Length > 0)
                        {
                            var id = procs[0].Id;
                            foreach (var p in procs) p.Dispose();
                            return id;
                        }
                    }
                    catch { }
                }

                return null;
            }
        }
    }

    public string CurrentPreset { get; private set; } = "General";

    public static readonly IReadOnlyList<string> AllPresets = new[]
    {
        "General",
        "General (ALT)",
        "General (ALT2)",
        "General (ALT3)",
        "General (ALT4)",
        "General (ALT5)",
        "General (ALT6)",
        "General (ALT7)",
        "General (ALT8)",
        "General (ALT9)",
        "General (ALT10)",
        "General (ALT11)",
        "General (ALT12)",
        "General (ALT13)",
        "General (SIMPLE FAKE)",
        "General (SIMPLE FAKE ALT)",
        "General (SIMPLE FAKE ALT2)",
        "General (FAKE TLS AUTO)",
        "General (FAKE TLS AUTO ALT)",
        "General (FAKE TLS AUTO ALT2)",
        "General (FAKE TLS AUTO ALT3)",
        "General (EXP)"
    };

    public static IReadOnlyList<string> AvailablePresets => AllPresets;

    public event Action<bool>? StateChanged;

    public ZapretEngine()
    {
        InitializeJobObject();
    }

    /// <summary>
    /// Starts winws.exe with the specified preset.
    /// </summary>
    public void Start(string presetName = "General")
    {
        lock (_lock)
        {
            Stop();
            KillLingeringWinws();

            var zapretDir = ResolveZapretDirectory();
            var binDir = Path.Combine(zapretDir, "bin");
            var listsDir = Path.Combine(zapretDir, "lists");
            var winwsExe = Path.Combine(binDir, "winws.exe");

            if (!File.Exists(winwsExe))
            {
                throw new FileNotFoundException($"winws.exe not found at: {winwsExe}");
            }

            EnsureUserLists(listsDir);

            var arguments = BuildArguments(presetName, zapretDir, binDir, listsDir);

            Process? proc = null;
            bool usedShellExecute = false;

            if (!IsAdministrator())
            {
                // Must elevate to load WinDivert kernel driver
                var elevatedPsi = new ProcessStartInfo
                {
                    FileName = winwsExe,
                    Arguments = arguments,
                    WorkingDirectory = binDir,
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                try
                {
                    proc = Process.Start(elevatedPsi);
                    usedShellExecute = true;
                }
                catch (System.ComponentModel.Win32Exception wEx)
                {
                    throw new InvalidOperationException("Для запуска службы обхода DPI требуются права Администратора (запрос UAC был отклонен).", wEx);
                }
            }
            else
            {
                var psi = new ProcessStartInfo
                {
                    FileName = winwsExe,
                    Arguments = arguments,
                    WorkingDirectory = binDir,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                try
                {
                    proc = Process.Start(psi);
                }
                catch (System.ComponentModel.Win32Exception wEx) when (wEx.NativeErrorCode == 740)
                {
                    var elevatedPsi = new ProcessStartInfo
                    {
                        FileName = winwsExe,
                        Arguments = arguments,
                        WorkingDirectory = binDir,
                        UseShellExecute = true,
                        Verb = "runas",
                        WindowStyle = ProcessWindowStyle.Hidden
                    };
                    proc = Process.Start(elevatedPsi);
                    usedShellExecute = true;
                }
            }

            _process = proc ?? throw new InvalidOperationException("Не удалось запустить процесс winws.exe.");
            _usedShellExecute = usedShellExecute;

            // Check if process immediately crashed or exited (only for non-ShellExecute where process object is directly queryable)
            if (!usedShellExecute)
            {
                try
                {
                    if (_process.WaitForExit(300))
                    {
                        int exitCode = _process.ExitCode;
                        _process.Dispose();
                        _process = null;
                        throw new InvalidOperationException($"Служба winws.exe завершилась сразу после запуска (код {exitCode}). Запустите OmniEye от имени Администратора.");
                    }
                }
                catch (InvalidOperationException)
                {
                    throw;
                }
                catch { }
            }
            else
            {
                // For ShellExecute UAC elevation: wait briefly and verify that winws process is alive in the system
                System.Threading.Thread.Sleep(300);
                if (!IsRunning)
                {
                    throw new InvalidOperationException("Служба winws.exe не смогла запуститься в среде Windows.");
                }
            }

            // Bind process to JobObject for guaranteed auto-kill on parent exit (if accessible)
            if (!usedShellExecute && _jobHandle != IntPtr.Zero && _process != null && !_process.HasExited)
            {
                try
                {
                    AssignProcessToJobObject(_jobHandle, _process.Handle);
                }
                catch { }
            }

            CurrentPreset = presetName;
            StateChanged?.Invoke(true);
        }
    }

    /// <summary>
    /// Checks if current process is running with elevated Administrator privileges.
    /// </summary>
    public static bool IsAdministrator()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Guarantees that any stale or orphaned winws.exe process and WinDivert driver are terminated.
    /// </summary>
    public static void KillLingeringWinws()
    {
        try
        {
            foreach (var p in Process.GetProcessesByName("winws"))
            {
                try
                {
                    p.Kill(entireProcessTree: true);
                    p.WaitForExit(400);
                }
                catch { }
                finally
                {
                    p.Dispose();
                }
            }
        }
        catch { }

        try
        {
            using var killProc = Process.Start(new ProcessStartInfo
            {
                FileName = "taskkill.exe",
                Arguments = "/F /IM winws.exe",
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden
            });
            killProc?.WaitForExit(500);
        }
        catch { }

        try
        {
            using var scProc = Process.Start(new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = "stop WinDivert",
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden
            });
            scProc?.WaitForExit(500);
        }
        catch { }
    }

    /// <summary>
    /// Ensures user-defined list files exist so winws.exe doesn't exit prematurely on missing files.
    /// </summary>
    public static void EnsureUserLists(string listsDir)
    {
        try
        {
            Directory.CreateDirectory(listsDir);

            var generalUser = Path.Combine(listsDir, "list-general-user.txt");
            if (!File.Exists(generalUser))
            {
                File.WriteAllText(generalUser, "# User-defined custom domains for DPI bypass\r\ndomain.example.abc\r\n");
            }

            var excludeUser = Path.Combine(listsDir, "list-exclude-user.txt");
            if (!File.Exists(excludeUser))
            {
                File.WriteAllText(excludeUser, "# User-defined excluded domains (bypass ignored)\r\ndomain.example.abc\r\n");
            }

            var ipsetExcludeUser = Path.Combine(listsDir, "ipset-exclude-user.txt");
            if (!File.Exists(ipsetExcludeUser))
            {
                File.WriteAllText(ipsetExcludeUser, "# User-defined excluded IP ranges (CIDR)\r\n203.0.113.113/32\r\n");
            }
        }
        catch { }
    }

    /// <summary>
    /// Stops winws.exe process and cleans up driver.
    /// </summary>
    public void Stop()
    {
        lock (_lock)
        {
            if (_process != null)
            {
                try
                {
                    if (!_process.HasExited)
                    {
                        _process.Kill(entireProcessTree: true);
                        _process.WaitForExit(2000);
                    }
                }
                catch { }
                finally
                {
                    _process.Dispose();
                    _process = null;
                }
            }

            KillLingeringWinws();
            _usedShellExecute = false;
            StateChanged?.Invoke(false);
        }
    }

    /// <summary>
    /// Restarts the winws.exe engine with the current or updated preset (e.g. after domain lists reload).
    /// </summary>
    public void Restart(string? preset = null)
    {
        lock (_lock)
        {
            var targetPreset = !string.IsNullOrWhiteSpace(preset) ? preset : CurrentPreset;
            if (IsRunning)
            {
                Stop();
                Start(targetPreset);
            }
            else
            {
                CurrentPreset = targetPreset;
            }
        }
    }

    /// <summary>
    /// Finds the Zapret directory across installed paths, output folder, or project source.
    /// </summary>
    public static string ResolveZapretDirectory()
    {
        var candidates = new[]
        {
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Zapret"),
            Path.Combine(AppContext.BaseDirectory, "Zapret"),
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "OmniEye.DpiBypass", "Zapret"),
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "zapret-discord-youtube-1.10.2"),
            @"D:\SPA_Full\OmniEye\OmniEye.DpiBypass\Zapret",
            @"D:\SPA_Full\OmniEye\zapret-discord-youtube-1.10.2"
        };

        foreach (var c in candidates)
        {
            try
            {
                var full = Path.GetFullPath(c);
                if (File.Exists(Path.Combine(full, "bin", "winws.exe")))
                {
                    return full;
                }
            }
            catch { }
        }

        throw new DirectoryNotFoundException("Could not locate Zapret assets directory with bin/winws.exe.");
    }

    /// <summary>
    /// Builds tested command line flags for the chosen preset with absolute paths.
    /// </summary>
    public static string BuildArguments(string preset, string binDir, string listsDir)
    {
        var zapretDir = Directory.GetParent(binDir)?.FullName ?? binDir;
        return BuildArguments(preset, zapretDir, binDir, listsDir);
    }

    /// <summary>
    /// Builds command line flags for the chosen preset by loading from batch file preset or using built-in defaults.
    /// </summary>
    public static string BuildArguments(string preset, string zapretDir, string binDir, string listsDir)
    {
        var batchArgs = TryParseBatchPreset(preset, zapretDir, binDir, listsDir);
        if (!string.IsNullOrEmpty(batchArgs))
        {
            return batchArgs;
        }

        string P(string file) => Path.Combine(binDir, file);
        string L(string file) => Path.Combine(listsDir, file);

        string listGeneral = L("list-general.txt");
        string listGoogle = L("list-google.txt");
        string listExclude = L("list-exclude.txt");
        string ipsetAll = L("ipset-all.txt");
        string ipsetExclude = L("ipset-exclude.txt");

        string quicGoogle = P("quic_initial_www_google_com.bin");
        string discordUdp = P("ACTIVE_DISCORD_UDP.bin");
        string tlsGoogle = P("tls_clienthello_www_google_com.bin");
        string tls4pda = P("tls_clienthello_4pda_to.bin");
        string stun = P("stun.bin");
        string tlsMax = P("tls_clienthello_max_ru.bin");

        switch (preset)
        {
            case "General (ALT)":
                return string.Join(" ", new[]
                {
                    "--wf-tcp=80,443,2053,2083,2087,2096,8443",
                    "--wf-udp=443,19294-19344,50000-50100",
                    $"--filter-udp=443 --hostlist=\"{listGeneral}\" --hostlist-exclude=\"{listExclude}\" --ipset-exclude=\"{ipsetExclude}\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{quicGoogle}\" --new",
                    $"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord=\"{discordUdp}\" --dpi-desync-fake-stun=\"{discordUdp}\" --dpi-desync-repeats=6 --new",
                    $"--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls=\"{tlsGoogle}\" --new",
                    $"--filter-tcp=443 --hostlist=\"{listGoogle}\" --ip-id=zero --dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls=\"{tlsGoogle}\" --new",
                    $"--filter-tcp=80,443 --hostlist=\"{listGeneral}\" --hostlist-exclude=\"{listExclude}\" --ipset-exclude=\"{ipsetExclude}\" --dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls=\"{stun}\" --dpi-desync-fake-tls=\"{tlsGoogle}\" --dpi-desync-fake-http=\"{tlsMax}\" --new",
                    $"--filter-udp=443 --ipset=\"{ipsetAll}\" --hostlist-exclude=\"{listExclude}\" --ipset-exclude=\"{ipsetExclude}\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{quicGoogle}\" --new",
                    $"--filter-tcp=80,443,8443 --ipset=\"{ipsetAll}\" --hostlist-exclude=\"{listExclude}\" --ipset-exclude=\"{ipsetExclude}\" --dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls=\"{stun}\" --dpi-desync-fake-tls=\"{tlsGoogle}\" --dpi-desync-fake-http=\"{tlsMax}\""
                });

            case "General (SIMPLE FAKE)":
                return string.Join(" ", new[]
                {
                    "--wf-tcp=80,443,2053,2083,2087,2096,8443",
                    "--wf-udp=443,19294-19344,50000-50100",
                    $"--filter-udp=443 --hostlist=\"{listGeneral}\" --hostlist-exclude=\"{listExclude}\" --ipset-exclude=\"{ipsetExclude}\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{quicGoogle}\" --new",
                    $"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord=\"{discordUdp}\" --dpi-desync-fake-stun=\"{discordUdp}\" --dpi-desync-repeats=6 --new",
                    $"--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fake-tls=\"{tlsGoogle}\" --new",
                    $"--filter-tcp=443 --hostlist=\"{listGoogle}\" --ip-id=zero --dpi-desync=hostfakesplit --dpi-desync-fooling=ts --dpi-desync-hostfakesplit-mod=host=www.google.com --new",
                    $"--filter-tcp=80,443 --hostlist=\"{listGeneral}\" --hostlist-exclude=\"{listExclude}\" --ipset-exclude=\"{ipsetExclude}\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fake-tls=\"{tlsGoogle}\" --dpi-desync-fake-http=\"{tlsMax}\" --new",
                    $"--filter-udp=443 --ipset=\"{ipsetAll}\" --hostlist-exclude=\"{listExclude}\" --ipset-exclude=\"{ipsetExclude}\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{quicGoogle}\" --new",
                    $"--filter-tcp=80,443,8443 --ipset=\"{ipsetAll}\" --hostlist-exclude=\"{listExclude}\" --ipset-exclude=\"{ipsetExclude}\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fake-tls=\"{tlsGoogle}\" --dpi-desync-fake-http=\"{tlsMax}\""
                });

            case "General (ALT2)":
            case "General":
            default:
                // Flowseal standard: Multisplit for TCP + Fake QUIC/Discord UDP
                return string.Join(" ", new[]
                {
                    "--wf-tcp=80,443,2053,2083,2087,2096,8443",
                    "--wf-udp=443,19294-19344,50000-50100",
                    $"--filter-udp=443 --hostlist=\"{listGeneral}\" --hostlist-exclude=\"{listExclude}\" --ipset-exclude=\"{ipsetExclude}\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{quicGoogle}\" --new",
                    $"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord=\"{discordUdp}\" --dpi-desync-fake-stun=\"{discordUdp}\" --dpi-desync-repeats=6 --new",
                    $"--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=\"{tlsGoogle}\" --new",
                    $"--filter-tcp=443 --hostlist=\"{listGoogle}\" --ip-id=zero --dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=\"{tlsGoogle}\" --new",
                    $"--filter-tcp=80,443 --hostlist=\"{listGeneral}\" --hostlist-exclude=\"{listExclude}\" --ipset-exclude=\"{ipsetExclude}\" --dpi-desync=multisplit --dpi-desync-split-seqovl=568 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=\"{tls4pda}\" --new",
                    $"--filter-udp=443 --ipset=\"{ipsetAll}\" --hostlist-exclude=\"{listExclude}\" --ipset-exclude=\"{ipsetExclude}\" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=\"{quicGoogle}\" --new",
                    $"--filter-tcp=80,443,8443 --ipset=\"{ipsetAll}\" --hostlist-exclude=\"{listExclude}\" --ipset-exclude=\"{ipsetExclude}\" --dpi-desync=multisplit --dpi-desync-split-seqovl=568 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=\"{tls4pda}\""
                });
        }
    }

    /// <summary>
    /// Attempts to parse winws.exe arguments directly from Flowseal's preset .bat file.
    /// </summary>
    public static string? TryParseBatchPreset(string presetName, string zapretDir, string binDir, string listsDir)
    {
        try
        {
            var searchDirs = new[]
            {
                Path.Combine(zapretDir, "presets"),
                zapretDir,
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Zapret", "presets"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Zapret"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "zapret-discord-youtube-1.10.2"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "OmniEye.DpiBypass", "Zapret", "presets"),
                @"D:\SPA_Full\OmniEye\OmniEye.DpiBypass\Zapret\presets",
                @"D:\SPA_Full\OmniEye\zapret-discord-youtube-1.10.2"
            };

            string? foundFile = null;
            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;

                var directCheck = Path.Combine(dir, $"{presetName}.bat");
                if (File.Exists(directCheck)) { foundFile = directCheck; break; }

                var lowerCheck = Path.Combine(dir, $"{presetName.ToLowerInvariant()}.bat");
                if (File.Exists(lowerCheck)) { foundFile = lowerCheck; break; }

                foreach (var file in Directory.GetFiles(dir, "*.bat"))
                {
                    if (string.Equals(Path.GetFileName(file), "service.bat", StringComparison.OrdinalIgnoreCase)) continue;
                    var nameOnly = Path.GetFileNameWithoutExtension(file);
                    if (string.Equals(nameOnly, presetName, StringComparison.OrdinalIgnoreCase))
                    {
                        foundFile = file;
                        break;
                    }
                }
                if (foundFile != null) break;
            }

            if (foundFile == null) return null;

            var lines = File.ReadAllLines(foundFile);
            var argsList = new List<string>();
            bool collecting = false;

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (!collecting)
                {
                    int winwsIdx = trimmed.IndexOf("winws.exe\"", StringComparison.OrdinalIgnoreCase);
                    if (winwsIdx >= 0)
                    {
                        collecting = true;
                        var afterWinws = trimmed.Substring(winwsIdx + "winws.exe\"".Length).TrimEnd('^').Trim();
                        if (!string.IsNullOrEmpty(afterWinws))
                        {
                            argsList.Add(afterWinws);
                        }
                    }
                }
                else
                {
                    if (trimmed.Length == 0 || trimmed.StartsWith("::") || trimmed.StartsWith("rem", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var part = trimmed.TrimEnd('^').Trim();
                    if (!string.IsNullOrEmpty(part))
                    {
                        argsList.Add(part);
                    }

                    if (!line.TrimEnd().EndsWith("^"))
                    {
                        break;
                    }
                }
            }

            if (argsList.Count == 0) return null;

            string full = string.Join(" ", argsList);
            string normalizedBin = binDir.TrimEnd('\\', '/') + "\\";
            string normalizedLists = listsDir.TrimEnd('\\', '/') + "\\";

            full = full.Replace("%BIN%", normalizedBin, StringComparison.OrdinalIgnoreCase)
                       .Replace("%LISTS%", normalizedLists, StringComparison.OrdinalIgnoreCase)
                       .Replace("%GameFilterTCP%", "12", StringComparison.OrdinalIgnoreCase)
                       .Replace("%GameFilterUDP%", "12", StringComparison.OrdinalIgnoreCase);

            return full;
        }
        catch
        {
            return null;
        }
    }

    #region Win32 JobObject Integration
    private void InitializeJobObject()
    {
        try
        {
            _jobHandle = CreateJobObject(IntPtr.Zero, null);
            if (_jobHandle != IntPtr.Zero)
            {
                var info = new JOBOBJECT_BASIC_LIMIT_INFORMATION
                {
                    LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                };
                var extendedInfo = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
                {
                    BasicLimitInformation = info
                };

                int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                IntPtr pInfo = Marshal.AllocHGlobal(length);
                try
                {
                    Marshal.StructureToPtr(extendedInfo, pInfo, false);
                    SetInformationJobObject(_jobHandle, JobObjectInfoType.ExtendedLimitInformation, pInfo, (uint)length);
                }
                finally
                {
                    Marshal.FreeHGlobal(pInfo);
                }
            }
        }
        catch { }
    }

    public void Dispose()
    {
        Stop();
        if (_jobHandle != IntPtr.Zero)
        {
            CloseHandle(_jobHandle);
            _jobHandle = IntPtr.Zero;
        }
    }

    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

    private enum JobObjectInfoType
    {
        ExtendedLimitInformation = 9
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryLimit;
        public UIntPtr PeakJobMemoryLimit;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr hJob, JobObjectInfoType infoType, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);
    #endregion
}
