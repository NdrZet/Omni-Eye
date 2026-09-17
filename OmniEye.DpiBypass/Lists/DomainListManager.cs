using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using OmniEye.DpiBypass.Zapret;

namespace OmniEye.DpiBypass.Lists;

/// <summary>
/// Manages loading, sanitizing, deduplicating, saving, importing, and exporting
/// custom domain lists (list-general.txt, list-google.txt, list-exclude.txt)
/// used by the native Zapret desynchronization engine.
/// </summary>
public class DomainListManager
{
    public const string ListGeneral = "list-general.txt";
    public const string ListGoogle = "list-google.txt";
    public const string ListExclude = "list-exclude.txt";

    public static readonly IReadOnlyList<string> StandardLists = new[]
    {
        ListGeneral,
        ListGoogle,
        ListExclude
    };

    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(15)
    };

    private static readonly Regex DomainRegex = new(
        @"^(\^|\*\.)?([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Gets the resolved lists directory where winws.exe looks for hostlists.
    /// </summary>
    public string ListsDirectory { get; }

    /// <summary>
    /// Gets the secondary project source lists directory (if exists) to persist changes across clean builds.
    /// </summary>
    public string? SourceListsDirectory { get; }

    private readonly bool _isCustomListsDir;

    public DomainListManager(string? customListsDir = null)
    {
        if (!string.IsNullOrWhiteSpace(customListsDir))
        {
            ListsDirectory = Path.GetFullPath(customListsDir);
            _isCustomListsDir = true;
        }
        else
        {
            var zapretDir = ZapretEngine.ResolveZapretDirectory();
            ListsDirectory = Path.Combine(zapretDir, "lists");
            _isCustomListsDir = false;
        }

        if (!Directory.Exists(ListsDirectory))
        {
            Directory.CreateDirectory(ListsDirectory);
        }

        // Detect project source directory if running in dev mode
        try
        {
            var devSourceDir = @"D:\SPA_Full\OmniEye\OmniEye.DpiBypass\Zapret\lists";
            if (Directory.Exists(devSourceDir) && !string.Equals(Path.GetFullPath(devSourceDir), Path.GetFullPath(ListsDirectory), StringComparison.OrdinalIgnoreCase))
            {
                SourceListsDirectory = Path.GetFullPath(devSourceDir);
            }
        }
        catch { }
    }

    /// <summary>
    /// Returns the absolute file path for a list name.
    /// </summary>
    public string GetListFilePath(string listFileName)
    {
        return Path.Combine(ListsDirectory, listFileName);
    }

    /// <summary>
    /// Loads all non-empty, non-comment domain entries from the specified list file.
    /// </summary>
    public List<string> LoadList(string listFileName)
    {
        var filePath = GetListFilePath(listFileName);
        if (!File.Exists(filePath))
        {
            // Try fallback to source dir if available
            if (SourceListsDirectory != null)
            {
                var srcPath = Path.Combine(SourceListsDirectory, listFileName);
                if (File.Exists(srcPath))
                {
                    filePath = srcPath;
                }
            }
        }

        if (!File.Exists(filePath))
        {
            return new List<string>();
        }

        var lines = File.ReadAllLines(filePath, Encoding.UTF8);
        var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#') || line.StartsWith(';'))
            {
                continue;
            }

            if (TrySanitizeDomain(line, out var cleanDomain, out _))
            {
                domains.Add(cleanDomain);
            }
            else
            {
                // Preserve exact line if it's already an existing entry in the list
                domains.Add(line.ToLowerInvariant());
            }
        }

        return domains.OrderBy(d => d, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// Saves the given collection of domains into the list file atomically,
    /// sorting alphabetically and deduplicating entries.
    /// </summary>
    public void SaveList(string listFileName, IEnumerable<string> domains)
    {
        var cleanSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in domains)
        {
            if (TrySanitizeDomain(item, out var clean, out _))
            {
                cleanSet.Add(clean);
            }
            else if (!string.IsNullOrWhiteSpace(item) && !item.Contains(' '))
            {
                cleanSet.Add(item.Trim().ToLowerInvariant());
            }
        }

        var sorted = cleanSet.OrderBy(d => d, StringComparer.OrdinalIgnoreCase).ToList();
        var targetFile = GetListFilePath(listFileName);
        var dir = Path.GetDirectoryName(targetFile);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var tempFile = targetFile + $".tmp_{Guid.NewGuid():N}";
        File.WriteAllLines(tempFile, sorted, new UTF8Encoding(false));

        try
        {
            File.Move(tempFile, targetFile, overwrite: true);
        }
        catch
        {
            // Direct write fallback
            File.WriteAllLines(targetFile, sorted, new UTF8Encoding(false));
            if (File.Exists(tempFile))
            {
                try { File.Delete(tempFile); } catch { }
            }
        }

        // Mirror to source directory if in development workspace and not running with custom isolated dir
        if (!_isCustomListsDir && SourceListsDirectory != null && Directory.Exists(SourceListsDirectory))
        {
            try
            {
                var srcTarget = Path.Combine(SourceListsDirectory, listFileName);
                File.WriteAllLines(srcTarget, sorted, new UTF8Encoding(false));
            }
            catch { }
        }
    }

    /// <summary>
    /// Sanitizes and validates a domain string entered by the user or read from an external source.
    /// Handles prefixes (^, *.), URLs (http://, https://), ports, query strings, and paths.
    /// </summary>
    public static bool TrySanitizeDomain(string input, out string cleanDomain, out string? errorMessage)
    {
        cleanDomain = string.Empty;
        errorMessage = null;

        if (string.IsNullOrWhiteSpace(input))
        {
            errorMessage = "Domain cannot be empty.";
            return false;
        }

        var s = input.Trim();

        // Detect Zapret prefix (^) or wildcard (*.)
        string prefix = string.Empty;
        if (s.StartsWith('^'))
        {
            prefix = "^";
            s = s[1..].Trim();
        }
        else if (s.StartsWith("*."))
        {
            prefix = "*.";
            s = s[2..].Trim();
        }

        // Strip http:// or https:// if user pasted full URL
        if (s.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            s = s[7..];
        }
        else if (s.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            s = s[8..];
        }

        // Strip trailing paths, queries, fragments
        var slashIdx = s.IndexOf('/');
        if (slashIdx >= 0)
        {
            s = s[..slashIdx];
        }
        var questIdx = s.IndexOf('?');
        if (questIdx >= 0)
        {
            s = s[..questIdx];
        }
        var hashIdx = s.IndexOf('#');
        if (hashIdx >= 0)
        {
            s = s[..hashIdx];
        }

        // Strip port (e.g. :443, :8080)
        var colonIdx = s.IndexOf(':');
        if (colonIdx >= 0)
        {
            s = s[..colonIdx];
        }

        s = s.Trim().TrimEnd('.');

        if (string.IsNullOrWhiteSpace(s))
        {
            errorMessage = "Invalid or empty domain after stripping protocol and path.";
            return false;
        }

        var candidate = prefix + s.ToLowerInvariant();

        // Validate structure
        if (!DomainRegex.IsMatch(candidate))
        {
            errorMessage = $"Domain '{candidate}' is not a valid hostname (e.g., example.com).";
            return false;
        }

        cleanDomain = candidate;
        return true;
    }

    /// <summary>
    /// Parses, sanitizes, and deduplicates domains from raw multiline text (e.g. from Notepad view).
    /// </summary>
    public static List<string> ParseRawText(string rawText)
    {
        if (string.IsNullOrWhiteSpace(rawText))
        {
            return new List<string>();
        }

        var lines = rawText.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        var cleanSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#') || line.StartsWith(';'))
            {
                continue;
            }

            if (TrySanitizeDomain(line, out var clean, out _))
            {
                cleanSet.Add(clean);
            }
            else if (!line.Contains(' ') && !line.Contains('\t') && (line.Contains('.') || line.Contains(':')))
            {
                cleanSet.Add(line.ToLowerInvariant());
            }
        }

        return cleanSet.OrderBy(d => d, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// Gets the raw text content of a list file for Notepad viewing.
    /// </summary>
    public string GetRawText(string listFileName)
    {
        var domains = LoadList(listFileName);
        return string.Join(Environment.NewLine, domains);
    }

    /// <summary>
    /// Opens the specified domain list file in the system default text editor (notepad.exe).
    /// </summary>
    public System.Diagnostics.Process? OpenInSystemEditor(string listFileName)
    {
        var filePath = GetListFilePath(listFileName);
        if (!File.Exists(filePath))
        {
            SaveList(listFileName, Enumerable.Empty<string>());
        }

        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "notepad.exe",
            Arguments = $"\"{filePath}\"",
            UseShellExecute = true
        };

        return System.Diagnostics.Process.Start(psi);
    }

    /// <summary>
    /// Exports the specified domain list to an external text file.
    /// </summary>
    public void ExportList(string listFileName, string targetFilePath)
    {
        var domains = LoadList(listFileName);
        var dir = Path.GetDirectoryName(targetFilePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
        File.WriteAllLines(targetFilePath, domains, new UTF8Encoding(false));
    }

    /// <summary>
    /// Imports domains from an external text file into the specified list,
    /// optionally merging with existing entries.
    /// </summary>
    public int ImportList(string listFileName, string sourceFilePath, bool mergeWithExisting = true)
    {
        if (!File.Exists(sourceFilePath))
        {
            throw new FileNotFoundException($"Source file not found: {sourceFilePath}");
        }

        var existing = mergeWithExisting ? LoadList(listFileName) : new List<string>();
        var countBefore = existing.Count;
        var existingSet = new HashSet<string>(existing, StringComparer.OrdinalIgnoreCase);

        var lines = File.ReadAllLines(sourceFilePath, Encoding.UTF8);
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#') || line.StartsWith(';'))
            {
                continue;
            }

            if (TrySanitizeDomain(line, out var clean, out _))
            {
                existingSet.Add(clean);
            }
        }

        SaveList(listFileName, existingSet);
        return existingSet.Count - countBefore;
    }

    /// <summary>
    /// Asynchronously downloads an online community hostlist and merges valid domains into the current list.
    /// </summary>
    public async Task<(int AddedCount, int TotalCount)> FetchCommunityListAsync(
        string listFileName,
        string url,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException("Invalid community list URL provided.", nameof(url));
        }

        using var response = await HttpClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        var lines = content.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);

        var current = LoadList(listFileName);
        var initialCount = current.Count;
        var set = new HashSet<string>(current, StringComparer.OrdinalIgnoreCase);

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#') || line.StartsWith(';'))
            {
                continue;
            }

            if (TrySanitizeDomain(line, out var clean, out _))
            {
                set.Add(clean);
            }
        }

        SaveList(listFileName, set);
        var added = set.Count - initialCount;
        return (added, set.Count);
    }
}
