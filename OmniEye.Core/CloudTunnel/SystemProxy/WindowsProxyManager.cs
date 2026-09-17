using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace OmniEye.Core.CloudTunnel.SystemProxy;

public static class WindowsProxyManager
{
    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
    private const int INTERNET_OPTION_REFRESH = 37;

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    public static void EnableProxy(string host, int port, bool bypassRussianDomains = true)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, true);
            if (key == null) return;

            string proxyServer = $"socks={host}:{port}";
            string proxyOverride = bypassRussianDomains
                ? "<local>;*.ru;*.рф;*.xn--p1ai;*.gosuslugi.ru;*.sberbank.ru;*.tbank.ru;*.yandex.ru;127.0.0.1;localhost"
                : "<local>;127.0.0.1;localhost";

            key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            key.SetValue("ProxyServer", proxyServer, RegistryValueKind.String);
            key.SetValue("ProxyOverride", proxyOverride, RegistryValueKind.String);

            NotifySettingsChanged();
        }
        catch { }
    }

    public static void DisableProxy()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, true);
            if (key == null) return;

            key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
            NotifySettingsChanged();
        }
        catch { }
    }

    public static bool IsProxyEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, false);
            if (key == null) return false;

            var val = key.GetValue("ProxyEnable");
            return val is int i && i == 1;
        }
        catch
        {
            return false;
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
