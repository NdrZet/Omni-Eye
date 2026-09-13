using System;
using System.IO;
using System.Linq;

namespace OmniEye.Core.Models;

/// <summary>
/// Represents an application approved to establish outbound network connections.
/// </summary>
public class WhitelistEntry
{
    public int Id { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public bool IsSigned { get; set; }
    public string? SignerSubject { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool IsEnabled { get; set; } = true;
    public string? GroupName { get; set; }

    public string AppGroup => !string.IsNullOrEmpty(GroupName) ? GroupName : DeriveAppGroup(FilePath, FileName);

    private static readonly System.Collections.Generic.HashSet<string> s_genericSystemDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "Program Files", "Program Files (x86)", "AppData", "Local", "Roaming", "LocalLow",
        "Windows", "System32", "SysWOW64", "Users", "Temp", "Tmp", "Desktop", "Downloads", "Documents"
    };

    private static readonly System.Collections.Generic.HashSet<string> s_genericSubDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "service", "services", "bin", "bin32", "bin64", "x64", "x86", "win32", "win64",
        "tap", "daemon", "daemons", "helper", "helpers", "plugins", "plugin", "driver",
        "drivers", "runtime", "tools", "core", "app", "app-bin", "resources", "vpn", "tunnel",
        "proxy", "application"
    };

    public static string DeriveAppGroup(string filePath, string fileName)
    {
        if (string.IsNullOrEmpty(filePath))
            return "Другие приложения";

        try
        {
            var dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir))
            {
                var dirName = Path.GetFileName(dir);
                var parent = Directory.GetParent(dir)?.FullName;
                var parentName = !string.IsNullOrEmpty(parent) ? Path.GetFileName(parent) : null;

                // 1. Squirrel / Electron versioned dirs (e.g. Discord\app-1.0.9257)
                if (dirName.StartsWith("app-", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(parentName))
                    return parentName;

                // 2. Versioned numerical directories (e.g. Chrome\Application\132.0.7977.83)
                if (dirName.All(c => char.IsDigit(c) || c == '.') && !string.IsNullOrEmpty(parentName))
                {
                    if (s_genericSubDirs.Contains(parentName))
                    {
                        var grandParent = Directory.GetParent(parent!)?.Name;
                        if (!string.IsNullOrEmpty(grandParent) && !s_genericSystemDirs.Contains(grandParent))
                            return grandParent;
                    }
                    if (!s_genericSystemDirs.Contains(parentName))
                        return parentName;
                }

                // 3. Generic helper/service/bin/tap/application subdirectories
                if (s_genericSubDirs.Contains(dirName) && !string.IsNullOrEmpty(parentName))
                {
                    if (s_genericSubDirs.Contains(parentName))
                    {
                        var grandParent = Directory.GetParent(parent!)?.Name;
                        if (!string.IsNullOrEmpty(grandParent) && !s_genericSystemDirs.Contains(grandParent))
                            return grandParent;
                    }
                    if (!s_genericSystemDirs.Contains(parentName))
                        return parentName;
                }

                // 4. Standard directory name if not generic system folder
                if (!s_genericSystemDirs.Contains(dirName))
                    return dirName;
            }
        }
        catch { }

        return Path.GetFileNameWithoutExtension(fileName);
    }
}

