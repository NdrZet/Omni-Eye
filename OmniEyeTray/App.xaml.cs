using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace OmniEyeTray;

public partial class App : System.Windows.Application
{
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

