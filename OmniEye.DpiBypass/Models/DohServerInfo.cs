using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace OmniEye.DpiBypass.Models;

public class DohServerInfo : INotifyPropertyChanged
{
    private string _name = string.Empty;
    private string _url = string.Empty;
    private string _directIp = string.Empty;
    private string? _secondaryIp;
    private string _hostHeader = string.Empty;
    private bool _isEnabled = true;
    private bool _isActiveDns = false;
    private long _latencyMs = -1;
    private int _consecutiveFailures = 0;
    private DateTime _lastChecked = DateTime.MinValue;

    public event PropertyChangedEventHandler? PropertyChanged;

    public string Name
    {
        get => _name;
        set => SetField(ref _name, value);
    }

    public string Url
    {
        get => _url;
        set => SetField(ref _url, value);
    }

    public string DirectIp
    {
        get => _directIp;
        set => SetField(ref _directIp, value);
    }

    public string? SecondaryIp
    {
        get => _secondaryIp;
        set => SetField(ref _secondaryIp, value);
    }

    public string HostHeader
    {
        get => _hostHeader;
        set => SetField(ref _hostHeader, value);
    }

    public bool IsEnabled
    {
        get => _isEnabled;
        set => SetField(ref _isEnabled, value);
    }

    public bool IsActiveDns
    {
        get => _isActiveDns;
        set => SetField(ref _isActiveDns, value);
    }

    public long LatencyMs
    {
        get => _latencyMs;
        set => SetField(ref _latencyMs, value);
    }

    public int ConsecutiveFailures
    {
        get => _consecutiveFailures;
        set
        {
            if (SetField(ref _consecutiveFailures, value))
            {
                OnPropertyChanged(nameof(IsDegraded));
            }
        }
    }

    public bool IsDegraded => _consecutiveFailures >= 3;

    public DateTime LastChecked
    {
        get => _lastChecked;
        set => SetField(ref _lastChecked, value);
    }

    public DohServerInfo() { }

    public DohServerInfo(string name, string url, string directIp, string hostHeader, string? secondaryIp = null)
    {
        Name = name;
        Url = url;
        DirectIp = directIp;
        HostHeader = hostHeader;
        SecondaryIp = secondaryIp;
    }

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }
}
