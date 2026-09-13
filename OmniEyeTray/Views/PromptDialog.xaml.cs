using System;
using System.Windows;
using System.Windows.Threading;
using OmniEye.Core.Models;
using OmniEyeTray.Services;

namespace OmniEyeTray.Views;

public partial class PromptDialog : Window
{
    private readonly InjectionPromptNotification _notification;
    private readonly DispatcherTimer _timer;
    private int _remainingSeconds;

    public string Decision { get; private set; } = "kill";

    public PromptDialog(InjectionPromptNotification notification)
    {
        InitializeComponent();
        _notification = notification;
        _remainingSeconds = notification.TimeoutSeconds > 0 ? notification.TimeoutSeconds : 60;

        TxtSourcePath.Text = string.IsNullOrEmpty(notification.SourcePath) ? "[Unknown]" : notification.SourcePath;
        TxtSourcePid.Text = $"PID: {notification.SourcePid}";
        TxtTargetPath.Text = string.IsNullOrEmpty(notification.TargetPath) ? "[Protected Process]" : notification.TargetPath;
        TxtTargetPid.Text = $"PID: {notification.TargetPid}";

        PbCountdown.Maximum = _remainingSeconds;
        PbCountdown.Value = _remainingSeconds;
        TxtTimer.Text = LocalizationManager.GetString("Alert_TimerFormat", _remainingSeconds);

        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _timer.Tick += Timer_Tick;
        _timer.Start();
    }

    private void Timer_Tick(object? sender, EventArgs e)
    {
        _remainingSeconds--;
        PbCountdown.Value = Math.Max(0, _remainingSeconds);
        TxtTimer.Text = LocalizationManager.GetString("Alert_TimerFormat", _remainingSeconds);

        if (_remainingSeconds <= 0)
        {
            _timer.Stop();
            // Default timeout action is Kill
            Decision = "kill";
            DialogResult = true;
            Close();
        }
    }

    private void BtnKill_Click(object sender, RoutedEventArgs e)
    {
        _timer.Stop();
        Decision = "kill";
        DialogResult = true;
        Close();
    }

    private void BtnIgnore_Click(object sender, RoutedEventArgs e)
    {
        _timer.Stop();
        Decision = "ignore";
        DialogResult = false;
        Close();
    }

    protected override void OnClosed(EventArgs e)
    {
        _timer.Stop();
        base.OnClosed(e);
    }
}
