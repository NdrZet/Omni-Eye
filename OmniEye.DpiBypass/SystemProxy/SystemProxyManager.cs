using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace OmniEye.DpiBypass.SystemProxy;

public static class SystemProxyManager
{
    private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
    private const int INTERNET_OPTION_REFRESH = 37;

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    private static int? _previousProxyEnable;
    private static string? _previousProxyServer;
    private static string? _previousProxyOverride;

    public static bool IsProxyEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, false);
            if (key != null)
            {
                var val = key.GetValue("ProxyEnable");
                return val is int i && i == 1;
            }
        }
        catch { }
        return false;
    }

    private static bool _processExitHooked;
    private static readonly object _lock = new();

    public static bool EnableProxy(string address, int port, string bypassList = "<local>;localhost;127.*")
    {
        lock (_lock)
        {
            if (!_processExitHooked)
            {
                AppDomain.CurrentDomain.ProcessExit += (s, e) => DisableProxy();
                _processExitHooked = true;
            }

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, true);
                if (key == null) return false;

                // Save previous settings if not yet saved
                if (_previousProxyEnable == null)
                {
                    _previousProxyEnable = key.GetValue("ProxyEnable") as int? ?? 0;
                    _previousProxyServer = key.GetValue("ProxyServer") as string ?? "";
                    _previousProxyOverride = key.GetValue("ProxyOverride") as string ?? "";
                }

            key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            key.SetValue("ProxyServer", $"{address}:{port}", RegistryValueKind.String);
            key.SetValue("ProxyOverride", bypassList, RegistryValueKind.String);

                NotifySettingsChanged();
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    public static bool DisableProxy()
    {
        lock (_lock)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, true);
                if (key == null) return false;

                if (_previousProxyEnable.HasValue)
                {
                    key.SetValue("ProxyEnable", _previousProxyEnable.Value, RegistryValueKind.DWord);
                    key.SetValue("ProxyServer", _previousProxyServer ?? "", RegistryValueKind.String);
                    key.SetValue("ProxyOverride", _previousProxyOverride ?? "", RegistryValueKind.String);
                    _previousProxyEnable = null;
                }
                else
                {
                    key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                }

                NotifySettingsChanged();
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    private static void NotifySettingsChanged()
    {
        try
        {
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }
        catch { }
    }
}
