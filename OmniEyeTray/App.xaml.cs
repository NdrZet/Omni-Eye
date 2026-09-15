using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace OmniEyeTray;

public partial class App : System.Windows.Application
{
    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetProcessDpiAwarenessContext(IntPtr dpiContext);

    static App()
    {
        try
        {
            // Enforce Windows 10/11 PerMonitorV2 (-4) DPI Awareness to eliminate DWM bitmap blur
            SetProcessDpiAwarenessContext(new IntPtr(-4));
        }
        catch { }
    }

    public App()
    {
        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
        {
            LogCrash(e.ExceptionObject as Exception);
        };

        DispatcherUnhandledException += (s, e) =>
        {
            LogCrash(e.Exception);
            e.Handled = false;
        };
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        OmniEyeTray.Services.LocalizationManager.Initialize();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            OmniEye.DpiBypass.Dns.SystemDnsManager.RestoreDns();
            OmniEye.DpiBypass.SystemProxy.SystemProxyManager.DisableProxy();
        }
        catch { }
        base.OnExit(e);
    }

    private static void LogCrash(Exception? ex)
    {
        if (ex == null) return;
        try
        {
            var msg = $"{DateTime.Now}: {ex}\nInner: {ex.InnerException}\n";
            File.AppendAllText(@"D:\SPA_Full\OmniEye\crash.log", msg);
            File.AppendAllText(@"C:\ProgramData\OmniEye\crash.log", msg);
            System.Windows.MessageBox.Show(ex.ToString(), "OmniEye Startup Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch { }
    }
}

