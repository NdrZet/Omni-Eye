using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using OmniEye.Core.Ipc;
using OmniEye.Core.Models;
using OmniEye.Core.Security;
using OmniEyeTray.Services;
using Wpf.Ui.Controls;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;

namespace OmniEyeTray.Views;

public partial class NetworkMonitorWindow : FluentWindow
{
    private readonly IpcClient _ipcClient;
    private readonly ObservableCollection<WhitelistEntry> _whitelistEntries;
    private readonly bool _isOutboundBlocked;
    private readonly Func<string, Task>? _onAddWhitelistWithDiscoveryAsync;
    private readonly ICollectionView _connectionsView;
    private readonly DispatcherTimer _refreshTimer;

    public ObservableCollection<NetworkConnectionInfo> NetworkConnections { get; set; } = new();

    public NetworkMonitorWindow(
        IpcClient ipcClient,
        ObservableCollection<WhitelistEntry> whitelistEntries,
        bool isOutboundBlocked,
        Func<string, Task>? onAddWhitelistWithDiscoveryAsync = null)
    {
        InitializeComponent();

        _ipcClient = ipcClient;
        _whitelistEntries = whitelistEntries;
        _isOutboundBlocked = isOutboundBlocked;
        _onAddWhitelistWithDiscoveryAsync = onAddWhitelistWithDiscoveryAsync;

        _connectionsView = CollectionViewSource.GetDefaultView(NetworkConnections);
        _connectionsView.Filter = FilterConnections;
        DgConnections.ItemsSource = _connectionsView;

        _refreshTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(3)
        };
        _refreshTimer.Tick += async (s, e) => await RefreshNetworkConnectionsAsync();

        LocalizationManager.LanguageChanged += OnLanguageChanged;

        Loaded += async (s, e) =>
        {
            _refreshTimer.Start();
            await RefreshNetworkConnectionsAsync();
        };

        Closed += (s, e) =>
        {
            _refreshTimer.Stop();
            LocalizationManager.LanguageChanged -= OnLanguageChanged;
        };
    }

    private void OnLanguageChanged()
    {
        Dispatcher.Invoke(() =>
        {
            foreach (var conn in NetworkConnections)
            {
                conn.StatusText = LocalizationManager.GetString(conn.StatusResourceKey);
            }
            _connectionsView?.Refresh();
            UpdateStatsAndCounter();
        });
    }

    private bool FilterConnections(object item)
    {
        if (item is not NetworkConnectionInfo conn) return false;

        // 1. Protocol filter
        if (CmbProtocolFilter?.SelectedItem is ComboBoxItem selectedProtocol)
        {
            string tag = selectedProtocol.Tag?.ToString() ?? "ALL";
            if (tag == "TCP" && conn.Protocol != NetworkProtocol.Tcp) return false;
            if (tag == "UDP" && conn.Protocol != NetworkProtocol.Udp) return false;
        }

        // 2. Status filter
        if (CmbStatusFilter?.SelectedItem is ComboBoxItem selectedStatus)
        {
            string statusTag = selectedStatus.Tag?.ToString() ?? "ALL";
            if (statusTag != "ALL")
            {
                bool matchesStatus = statusTag switch
                {
                    "WHITELISTED" => conn.EnforcementStatus == ZeroTrustEnforcementStatus.Whitelisted,
                    "BLOCKED" => conn.EnforcementStatus == ZeroTrustEnforcementStatus.Blocked,
                    "EXCEPTION" => conn.EnforcementStatus == ZeroTrustEnforcementStatus.SystemException,
                    "PERMISSIVE" => conn.EnforcementStatus == ZeroTrustEnforcementStatus.Permissive,
                    _ => true
                };
                if (!matchesStatus) return false;
            }
        }

        // 3. Search query filter
        string search = TxtConnectionSearch?.Text?.Trim() ?? string.Empty;
        if (!string.IsNullOrEmpty(search))
        {
            bool match = conn.ProcessName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                         conn.ProcessId.ToString().Contains(search, StringComparison.OrdinalIgnoreCase) ||
                         conn.LocalEndpoint.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                         conn.RemoteEndpoint.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                         conn.ProcessPath.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                         conn.State.Contains(search, StringComparison.OrdinalIgnoreCase);

            if (!match) return false;
        }

        return true;
    }

    private void TxtConnectionSearch_TextChanged(object sender, TextChangedEventArgs e)
    {
        _connectionsView?.Refresh();
        UpdateStatsAndCounter();
    }

    private void CmbProtocolFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _connectionsView?.Refresh();
        UpdateStatsAndCounter();
    }

    private void CmbStatusFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _connectionsView?.Refresh();
        UpdateStatsAndCounter();
    }

    private async void BtnRefreshConnections_Click(object sender, RoutedEventArgs e)
    {
        BtnRefreshConnections.IsEnabled = false;
        try
        {
            await RefreshNetworkConnectionsAsync();
        }
        finally
        {
            BtnRefreshConnections.IsEnabled = true;
        }
    }

    private void BtnExitFullScreen_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void Window_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Escape)
        {
            Close();
        }
    }

    private async void BtnAddConnectionToWhitelist_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is string exePath && !string.IsNullOrEmpty(exePath))
        {
            if (File.Exists(exePath))
            {
                if (_onAddWhitelistWithDiscoveryAsync != null)
                {
                    await _onAddWhitelistWithDiscoveryAsync(exePath);
                }
                else
                {
                    await _ipcClient.AddToWhitelistAsync(exePath, bypassSignature: true);
                }
                await RefreshNetworkConnectionsAsync();
            }
            else
            {
                System.Windows.MessageBox.Show($"File not found: {exePath}", LocalizationManager.GetString("Msg_ErrorTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }

    private async Task RefreshNetworkConnectionsAsync()
    {
        try
        {
            var whitelistedPaths = _whitelistEntries
                .Select(e => e.FilePath)
                .Where(p => !string.IsNullOrEmpty(p))
                .ToList();

            var connections = await Task.Run(() =>
                NetworkMonitorService.GetActiveConnections(whitelistedPaths, _isOutboundBlocked));

            foreach (var conn in connections)
            {
                conn.StatusText = LocalizationManager.GetString(conn.StatusResourceKey);
            }

            NetworkConnections.Clear();
            foreach (var c in connections)
            {
                NetworkConnections.Add(c);
            }

            _connectionsView?.Refresh();
            UpdateStatsAndCounter();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[NetMonFull] Error refreshing: {ex.Message}");
        }
    }

    private void UpdateStatsAndCounter()
    {
        if (TxtConnectionsCount == null) return;

        int filteredCount = _connectionsView?.Cast<object>().Count() ?? NetworkConnections.Count;
        string fmt = LocalizationManager.GetString("NetMon_CountFormat");
        TxtConnectionsCount.Text = string.Format(fmt, filteredCount);

        int tcpCount = NetworkConnections.Count(c => c.Protocol == NetworkProtocol.Tcp);
        int udpCount = NetworkConnections.Count(c => c.Protocol == NetworkProtocol.Udp);
        int whitelisted = NetworkConnections.Count(c => c.EnforcementStatus == ZeroTrustEnforcementStatus.Whitelisted);
        int blocked = NetworkConnections.Count(c => c.EnforcementStatus == ZeroTrustEnforcementStatus.Blocked);
        int exceptions = NetworkConnections.Count(c => c.EnforcementStatus == ZeroTrustEnforcementStatus.SystemException);

        TxtStatTcp.Text = $"TCP: {tcpCount}";
        TxtStatUdp.Text = $"UDP: {udpCount}";
        TxtStatWhitelisted.Text = $"{LocalizationManager.GetString("NetMon_StatusWhitelisted")}: {whitelisted}";
        TxtStatBlocked.Text = $"{LocalizationManager.GetString("NetMon_StatusBlocked")}: {blocked}";
        TxtStatExceptions.Text = $"{LocalizationManager.GetString("NetMon_StatusException")}: {exceptions}";
    }
}
