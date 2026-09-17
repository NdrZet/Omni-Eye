using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Forms;
using Microsoft.Win32;
using OmniEye.Core.Ipc;
using OmniEye.Core.Models;
using OmniEye.Core.Security;
using OmniEye.DpiBypass.Dns;
using OmniEye.DpiBypass.Lists;
using OmniEye.DpiBypass.Models;
using OmniEye.DpiBypass.Zapret;
using OmniEye.Core.CloudTunnel;
using OmniEye.Core.CloudTunnel.Resources;
using OmniEye.Core.CloudTunnel.SystemProxy;
using OmniEyeTray.Services;
using OmniEyeTray.Views;
using Wpf.Ui.Controls;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxResult = System.Windows.MessageBoxResult;

namespace OmniEyeTray;

public partial class MainWindow : FluentWindow
{
    private readonly IpcClient _ipcClient;
    private NotifyIcon? _notifyIcon;
    private bool _isDeveloperMode = false;
    private bool _isOutboundBlocked = true;
    private bool _reallyExit = false;
    private readonly ICollectionView _whitelistView;
    private readonly ICollectionView _connectionsView;
    private readonly System.Windows.Threading.DispatcherTimer _netMonTimer;
    private readonly System.Windows.Threading.DispatcherTimer _dpiTelemetryTimer;
    private readonly ZapretEngine _zapretEngine = new();
    private readonly CloudTunnelManager _cloudTunnelManager = new(CloudTunnelConfig.Load());
    private readonly DohResolverPool _dohPool = new();
    private readonly DomainListManager _domainListManager = new();
    private string _activeSelectedList = DomainListManager.ListGeneral;
    private readonly ObservableCollection<string> _allDomainsForCurrentList = new();
    private readonly ObservableCollection<string> _filteredDomains = new();
    private bool _isNotepadViewMode = false;
    private bool _suppressNotepadTextSync = false;
    private string _currentTab = "Dashboard";
    private int _lastBlockedAttempts = 0;
    private bool _isDpiBypassActive = false;

    public ObservableCollection<WhitelistEntry> WhitelistEntries { get; set; } = new();
    public ObservableCollection<NetworkConnectionInfo> NetworkConnections { get; set; } = new();
    public ObservableCollection<DohServerInfo> DohServers { get; set; } = new();

    public MainWindow()
    {
        InitializeComponent();
        _ipcClient = new IpcClient();
        _ipcClient.ConnectionChanged += OnConnectionChanged;
        _ipcClient.InjectionPromptReceived += OnInjectionPromptReceived;

        _whitelistView = CollectionViewSource.GetDefaultView(WhitelistEntries);
        _whitelistView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(WhitelistEntry.AppGroup)));
        _whitelistView.SortDescriptions.Add(new SortDescription(nameof(WhitelistEntry.AppGroup), ListSortDirection.Ascending));
        _whitelistView.SortDescriptions.Add(new SortDescription(nameof(WhitelistEntry.FileName), ListSortDirection.Ascending));
        ListAppGroups.ItemsSource = _whitelistView;

        _connectionsView = CollectionViewSource.GetDefaultView(NetworkConnections);
        _connectionsView.Filter = FilterConnections;
        DgConnections.ItemsSource = _connectionsView;

        _netMonTimer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(3)
        };
        _netMonTimer.Tick += async (s, e) => await RefreshNetworkConnectionsAsync();

        ItemsDohServers.ItemsSource = DohServers;
        foreach (var s in _dohPool.Servers)
        {
            DohServers.Add(s);
        }

        CmbZapretPreset.ItemsSource = ZapretEngine.AvailablePresets;
        CmbZapretPreset.SelectedItem = "General";

        ItemsDomainList.ItemsSource = _filteredDomains;
        LoadDomainList(_activeSelectedList);

        _dpiTelemetryTimer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(2)
        };
        _dpiTelemetryTimer.Tick += (s, e) => UpdateDpiTelemetry();

        InitializeTrayIcon();

        // Language selector
        CmbLanguage.ItemsSource = LocalizationManager.SupportedLanguages;
        CmbLanguage.SelectedValue = LocalizationManager.CurrentLanguage;
        LocalizationManager.LanguageChanged += OnLanguageChanged;

        SourceInitialized += (s, e) => ApplyWindows11Style(this);
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;

        // Wire navigation RadioButtons after InitializeComponent has finished building all views
        NavDashboard.Checked += NavDashboard_Click;
        NavFirewall.Checked += NavFirewall_Click;
        NavDpiBypass.Checked += NavDpiBypass_Click;
        NavCloudTunnel.Checked += NavCloudTunnel_Click;
        NavInjection.Checked += NavInjection_Click;
        NavSettings.Checked += NavSettings_Click;

        _cloudTunnelManager.StateChanged += () => Dispatcher.Invoke(UpdateCloudTunnelUI);
        if (_cloudTunnelManager.Config.IsEnabled)
        {
            _cloudTunnelManager.Start();
        }
        else if (_cloudTunnelManager.Config.WorkerDomains.Count > 0)
        {
            _ = Task.Run(async () => await _cloudTunnelManager.PingWorkerAsync());
        }
        UpdateCloudTunnelUI();
    }

    private void CmbLanguage_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (CmbLanguage.SelectedValue is string code)
        {
            LocalizationManager.SetLanguage(code);
        }
    }

    private void OnLanguageChanged()
    {
        Dispatcher.Invoke(() =>
        {
            if (CmbLanguage.SelectedValue as string != LocalizationManager.CurrentLanguage)
            {
                CmbLanguage.SelectedValue = LocalizationManager.CurrentLanguage;
            }

            switch (_currentTab)
            {
                case "Dashboard":
                    TxtPageTitle.Text = LocalizationManager.GetString("Dash_Title");
                    TxtPageSubtitle.Text = LocalizationManager.GetString("Dash_Subtitle");
                    break;
                case "Firewall":
                    TxtPageTitle.Text = LocalizationManager.GetString("Firewall_Title");
                    TxtPageSubtitle.Text = LocalizationManager.GetString("Firewall_Subtitle");
                    break;
                case "NetworkMonitor":
                    TxtPageTitle.Text = LocalizationManager.GetString("NetMon_Title");
                    TxtPageSubtitle.Text = LocalizationManager.GetString("NetMon_Subtitle");
                    break;
                case "Injection":
                    TxtPageTitle.Text = LocalizationManager.GetString("Injection_Title");
                    TxtPageSubtitle.Text = LocalizationManager.GetString("Injection_Subtitle");
                    break;
                case "Settings":
                    TxtPageTitle.Text = LocalizationManager.GetString("Settings_Title");
                    TxtPageSubtitle.Text = LocalizationManager.GetString("Settings_Subtitle");
                    break;
                case "DpiBypass":
                    TxtPageTitle.Text = LocalizationManager.GetString("DpiBypass_Title");
                    TxtPageSubtitle.Text = LocalizationManager.GetString("DpiBypass_Subtitle");
                    break;
            }

            UpdateDevModeUI(_isDeveloperMode);

            if (_ipcClient.IsConnected)
            {
                TxtServiceStatus.Text = LocalizationManager.GetString("Status_ServiceConnected");
            }
            else
            {
                TxtServiceStatus.Text = LocalizationManager.GetString("Status_ServiceOffline");
            }

            UpdateFirewallPolicyUI(_isOutboundBlocked);

            foreach (var conn in NetworkConnections)
            {
                conn.StatusText = LocalizationManager.GetString(conn.StatusResourceKey);
            }
            _connectionsView?.Refresh();
            UpdateConnectionsCountBadge();

            int groupCount = WhitelistEntries.Select(x => x.AppGroup).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            TxtCardWhitelistCount.Text = LocalizationManager.GetString("Metric_WhitelistCountFormat", groupCount, WhitelistEntries.Count);
            TxtCardAttempts.Text = LocalizationManager.GetString("Metric_BlockedAttemptsFormat", _lastBlockedAttempts);

            UpdateTrayMenu();
        });
    }

    private void UpdateTrayMenu()
    {
        if (_notifyIcon?.ContextMenuStrip == null) return;
        var menu = _notifyIcon.ContextMenuStrip;
        menu.Items.Clear();
        menu.Items.Add(LocalizationManager.GetString("Tray_OpenDashboard"), null, (s, e) => ShowAndActivate());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(LocalizationManager.GetString("Tray_Exit"), null, (s, e) =>
        {
            _reallyExit = true;
            Close();
        });
    }

    private void InitializeTrayIcon()
    {
        Icon? appIcon = null;
        try
        {
            var icoPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "app.ico");
            if (File.Exists(icoPath))
            {
                appIcon = new Icon(icoPath);
            }
        }
        catch { }

        _notifyIcon = new NotifyIcon
        {
            Icon = appIcon ?? SystemIcons.Shield,
            Text = "OmniEye Zero-Trust System",
            Visible = true
        };

        var contextMenu = new ContextMenuStrip();
        _notifyIcon.ContextMenuStrip = contextMenu;
        UpdateTrayMenu();
        _notifyIcon.DoubleClick += (s, e) => ShowAndActivate();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        await ConnectAndRefreshAsync();
    }

    private async Task ConnectAndRefreshAsync()
    {
        TxtServiceStatus.Text = LocalizationManager.GetString("Status_Connecting");
        BadgeStatus.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(51, 37, 8));
        BadgeStatus.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(110, 77, 12));
        TxtServiceStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 200, 59));

        bool connected = await _ipcClient.ConnectAsync();
        if (connected)
        {
            await RefreshDataAsync();
        }
        else
        {
            TxtServiceStatus.Text = LocalizationManager.GetString("Status_ServiceOffline");
            BadgeStatus.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(59, 23, 26));
            BadgeStatus.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(107, 35, 41));
            TxtServiceStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 153, 164));
        }
    }

    private void OnConnectionChanged(bool isConnected)
    {
        Dispatcher.Invoke(() =>
        {
            if (isConnected)
            {
                TxtServiceStatus.Text = LocalizationManager.GetString("Status_ServiceConnected");
                BadgeStatus.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(19, 56, 33));
                BadgeStatus.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(30, 97, 53));
                TxtServiceStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(108, 203, 95));
            }
            else
            {
                TxtServiceStatus.Text = LocalizationManager.GetString("Status_ServiceOffline");
                BadgeStatus.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(59, 23, 26));
                BadgeStatus.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(107, 35, 41));
                TxtServiceStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 153, 164));
            }
        });
    }

    private void OnInjectionPromptReceived(InjectionPromptNotification notification)
    {
        Dispatcher.Invoke(() =>
        {
            // Show alert in tray
            _notifyIcon?.ShowBalloonTip(
                5000,
                LocalizationManager.GetString("Tray_AlertTitle"),
                LocalizationManager.GetString("Tray_AlertMsg", notification.SourcePid, Path.GetFileName(notification.TargetPath)),
                ToolTipIcon.Warning);

            // Display Topmost Prompt Dialog
            var dialog = new PromptDialog(notification);
            dialog.ShowDialog();

            string decision = dialog.Decision;
            _ = _ipcClient.SendPromptDecisionAsync(notification.PromptId, decision);
        });
    }

    private async Task RefreshDataAsync()
    {
        var status = await _ipcClient.GetStatusAsync();
        if (status != null)
        {
            _lastBlockedAttempts = status.BlockedAttemptsCount;
            UpdateDevModeUI(status.DeveloperMode);
            TxtCardAttempts.Text = LocalizationManager.GetString("Metric_BlockedAttemptsFormat", status.BlockedAttemptsCount);
            UpdateFirewallPolicyUI(status.OutboundBlocked);
        }

        var wl = await _ipcClient.GetWhitelistAsync();
        if (wl != null)
        {
            WhitelistEntries.Clear();
            foreach (var entry in wl.Entries)
            {
                WhitelistEntries.Add(entry);
            }
            _whitelistView?.Refresh();
            int groupCount = WhitelistEntries.Select(x => x.AppGroup).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            TxtCardWhitelistCount.Text = LocalizationManager.GetString("Metric_WhitelistCountFormat", groupCount, WhitelistEntries.Count);
        }
    }

    private async void BtnRefresh_Click(object sender, RoutedEventArgs e)
    {
        await ConnectAndRefreshAsync();
    }

    private async void BtnAdd_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = LocalizationManager.GetString("Action_AddApp"),
            Filter = "Executables (*.exe)|*.exe|All Files (*.*)|*.*"
        };

        if (dialog.ShowDialog() != true)
            return;

        await AddExecutableToWhitelistWithDiscoveryAsync(dialog.FileName);
    }

    private async void BtnAddConnectionToWhitelist_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.FrameworkElement elem && elem.Tag is string exePath && !string.IsNullOrEmpty(exePath))
        {
            if (File.Exists(exePath))
            {
                await AddExecutableToWhitelistWithDiscoveryAsync(exePath);
                await RefreshNetworkConnectionsAsync();
            }
            else
            {
                MessageBox.Show($"File not found: {exePath}", LocalizationManager.GetString("Msg_ErrorTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }

    private async Task AddExecutableToWhitelistWithDiscoveryAsync(string primaryFilePath)
    {
        var appName = Path.GetFileNameWithoutExtension(primaryFilePath);

        // 1. Discover companion binaries in the same application directory tree
        var discovered = DiscoverCompanionBinaries(primaryFilePath);

        if (discovered.Count > 1)
        {
            // Show Companion Discovery Dialog
            var discoveryDialog = new CompanionDiscoveryDialog(appName, discovered)
            {
                Owner = this
            };

            if (discoveryDialog.ShowDialog() == true)
            {
                var selectedItems = discoveryDialog.SelectedItems;
                if (selectedItems.Count == 0)
                    return;

                int addedCount = 0;
                var errors = new System.Text.StringBuilder();

                foreach (var item in selectedItems)
                {
                    bool bypass = false;
                    if (!item.IsSigned && _isDeveloperMode)
                    {
                        bypass = true;
                    }

                    var resp = await _ipcClient.AddToWhitelistAsync(item.FilePath, bypass);
                    if (resp != null && resp.Success)
                    {
                        addedCount++;
                    }
                    else if (resp != null)
                    {
                        errors.AppendLine($"{item.FileName}: {resp.Message}");
                    }
                }

                await RefreshDataAsync();

                if (errors.Length == 0)
                {
                    MessageBox.Show(
                        LocalizationManager.GetString("Msg_AddedGroupSuccess", addedCount, appName),
                        LocalizationManager.GetString("Msg_SuccessTitle"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show(
                        $"Added: {addedCount}.\nErrors:\n{errors}",
                        LocalizationManager.GetString("Msg_ErrorTitle"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }
            }
            return;
        }

        // Fallback: Single binary without companion executables
        var sig = AuthenticodeVerifier.VerifyFile(primaryFilePath);
        bool bypassSignature = false;
        if (!sig.IsValid)
        {
            if (!_isDeveloperMode)
            {
                MessageBox.Show(
                    LocalizationManager.GetString("Msg_UnsignedStrictError", sig.StatusMessage),
                    LocalizationManager.GetString("Msg_SecurityErrorTitle"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                return;
            }
            else
            {
                var choice = MessageBox.Show(
                    LocalizationManager.GetString("Msg_UnsignedDevWarning", sig.StatusMessage),
                    LocalizationManager.GetString("Msg_DevConfirmTitle"),
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (choice != MessageBoxResult.Yes)
                    return;

                bypassSignature = true;
            }
        }
        else
        {
            var choice = MessageBox.Show(
                LocalizationManager.GetString("Msg_SignatureValid", sig.SignerSubject),
                LocalizationManager.GetString("Msg_SignatureValidTitle"),
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);

            if (choice != MessageBoxResult.Yes)
                return;
        }

        var singleResp = await _ipcClient.AddToWhitelistAsync(primaryFilePath, bypassSignature);
        if (singleResp != null && singleResp.Success)
        {
            MessageBox.Show(LocalizationManager.GetString("Msg_AddedSuccess"), LocalizationManager.GetString("Msg_SuccessTitle"), MessageBoxButton.OK, MessageBoxImage.Information);
            await RefreshDataAsync();
        }
        else
        {
            MessageBox.Show($"{LocalizationManager.GetString("Msg_ErrorTitle")}: {singleResp?.Message ?? "No response"}", LocalizationManager.GetString("Msg_ErrorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private List<OmniEyeTray.Models.DiscoveredBinaryItem> DiscoverCompanionBinaries(string primaryFilePath)
    {
        var results = new List<OmniEyeTray.Models.DiscoveredBinaryItem>();
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var primaryDir = Path.GetDirectoryName(primaryFilePath);
        if (string.IsNullOrEmpty(primaryDir) || !Directory.Exists(primaryDir))
            return results;

        var searchDirs = new List<string> { primaryDir };

        // Also inspect parent directory if appropriate (e.g. Discord/app-X.X.X parent folder contains Update.exe)
        var parentDir = Directory.GetParent(primaryDir)?.FullName;
        if (!string.IsNullOrEmpty(parentDir) && Directory.Exists(parentDir))
        {
            var parentName = Path.GetFileName(parentDir);
            if (!string.Equals(parentName, "Program Files", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(parentName, "Program Files (x86)", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(parentName, "AppData", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(parentName, "Local", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(parentName, "Roaming", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(parentName, "Windows", StringComparison.OrdinalIgnoreCase))
            {
                searchDirs.Add(parentDir);
            }
        }

        // Also check immediate subdirectories (e.g., tap, bin, helper)
        try
        {
            foreach (var sub in Directory.GetDirectories(primaryDir))
            {
                searchDirs.Add(sub);
            }
        }
        catch { }

        var candidateFiles = new List<string>();
        foreach (var dir in searchDirs)
        {
            try
            {
                if (Directory.Exists(dir))
                {
                    candidateFiles.AddRange(Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly));
                }
            }
            catch { }
        }

        foreach (var candidate in candidateFiles)
        {
            var fullCandidate = Path.GetFullPath(candidate);
            if (!seenPaths.Add(fullCandidate))
                continue;

            var fileName = Path.GetFileName(fullCandidate);
            bool isPrimary = string.Equals(fullCandidate, primaryFilePath, StringComparison.OrdinalIgnoreCase);
            bool isAlreadyAdded = WhitelistEntries.Any(w => string.Equals(w.FilePath, fullCandidate, StringComparison.OrdinalIgnoreCase));

            string role = DetermineBinaryRole(fileName, isPrimary);
            var sig = AuthenticodeVerifier.VerifyFile(fullCandidate);

            bool isUninstaller = fileName.Contains("unins", StringComparison.OrdinalIgnoreCase) ||
                                 fileName.Contains("uninstall", StringComparison.OrdinalIgnoreCase) ||
                                 fileName.Contains("maintenancetool", StringComparison.OrdinalIgnoreCase);

            bool shouldSelect = (isPrimary || !isUninstaller) && !isAlreadyAdded;

            results.Add(new OmniEyeTray.Models.DiscoveredBinaryItem
            {
                FilePath = fullCandidate,
                FileName = fileName,
                Role = role + (isAlreadyAdded ? $" {LocalizationManager.GetString("Role_AlreadyInList")}" : ""),
                IsSigned = sig.IsValid,
                SignerSubject = sig.SignerSubject,
                IsAlreadyWhitelisted = isAlreadyAdded,
                IsSelected = shouldSelect
            });
        }

        return results.OrderByDescending(x => string.Equals(x.FilePath, primaryFilePath, StringComparison.OrdinalIgnoreCase))
                      .ThenBy(x => x.FileName)
                      .ToList();
    }

    private static string DetermineBinaryRole(string fileName, bool isPrimary)
    {
        if (isPrimary)
            return LocalizationManager.GetString("Role_PrimaryApp");

        var lower = fileName.ToLowerInvariant();
        if (lower.Contains("service"))
            return LocalizationManager.GetString("Role_Service");
        if (lower.Contains("tun") || lower.Contains("vpn") || lower.Contains("wireguard") || lower.Contains("openvpn") || lower.Contains("proxy"))
            return LocalizationManager.GetString("Role_Tunnel");
        if (lower.Contains("update") || lower.Contains("upgrade") || lower.Contains("installer"))
            return LocalizationManager.GetString("Role_Update");
        if (lower.Contains("helper") || lower.Contains("crash") || lower.Contains("reporter"))
            return LocalizationManager.GetString("Role_Helper");
        if (lower.Contains("unins") || lower.Contains("maintenancetool"))
            return LocalizationManager.GetString("Role_Uninstaller");

        return LocalizationManager.GetString("Role_Companion");
    }

    private void BtnRemove_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show("Click ✕ on file or Delete Group to remove.", LocalizationManager.GetString("Msg_DeleteEntryTitle"), MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async void BtnDeleteGroup_Click(object sender, RoutedEventArgs e)
    {
        e.Handled = true;
        if (sender is System.Windows.Controls.Button btn && btn.DataContext is CollectionViewGroup group)
        {
            var entries = group.Items.OfType<WhitelistEntry>().ToList();
            if (entries.Count == 0) return;

            var choice = MessageBox.Show(
                LocalizationManager.GetString("Msg_DeleteGroupConfirm", group.Name, entries.Count),
                LocalizationManager.GetString("Msg_DeleteGroupTitle"),
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (choice == MessageBoxResult.Yes)
            {
                foreach (var entry in entries)
                {
                    await _ipcClient.RemoveFromWhitelistAsync(entry.Id);
                }
                await RefreshDataAsync();
            }
        }
    }

    private async void BtnDeleteEntry_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn && btn.DataContext is WhitelistEntry entry)
        {
            var choice = MessageBox.Show(
                LocalizationManager.GetString("Msg_DeleteEntryConfirm", entry.FileName),
                LocalizationManager.GetString("Msg_DeleteEntryTitle"),
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (choice == MessageBoxResult.Yes)
            {
                var resp = await _ipcClient.RemoveFromWhitelistAsync(entry.Id);
                if (resp != null && resp.Success)
                {
                    await RefreshDataAsync();
                }
                else
                {
                    MessageBox.Show($"{LocalizationManager.GetString("Msg_ErrorTitle")}: {resp?.Message ?? "No response"}", LocalizationManager.GetString("Msg_ErrorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }
    }

    private void NavDashboard_Click(object sender, RoutedEventArgs e)
    {
        _currentTab = "Dashboard";
        ShowView(ViewDashboard, LocalizationManager.GetString("Dash_Title"), LocalizationManager.GetString("Dash_Subtitle"));
    }

    private void NavFirewall_Click(object sender, RoutedEventArgs e)
    {
        _currentTab = "Firewall";
        ShowView(ViewFirewall, LocalizationManager.GetString("Firewall_Title"), LocalizationManager.GetString("Firewall_Subtitle"));
    }

    private void NavDpiBypass_Click(object sender, RoutedEventArgs e)
    {
        _currentTab = "DpiBypass";
        ShowView(ViewDpiBypass, LocalizationManager.GetString("DpiBypass_Title"), LocalizationManager.GetString("DpiBypass_Subtitle"));
        UpdateDpiTelemetry();
    }

    private void NavCloudTunnel_Click(object sender, RoutedEventArgs e)
    {
        _currentTab = "CloudTunnel";
        ShowView(ViewCloudTunnel, LocalizationManager.GetString("CloudTunnel_Title"), LocalizationManager.GetString("CloudTunnel_Subtitle"));
        UpdateCloudTunnelUI();
    }

    private void NavInjection_Click(object sender, RoutedEventArgs e)
    {
        _currentTab = "Injection";
        ShowView(ViewInjection, LocalizationManager.GetString("Injection_Title"), LocalizationManager.GetString("Injection_Subtitle"));
    }

    private void NavSettings_Click(object sender, RoutedEventArgs e)
    {
        _currentTab = "Settings";
        ShowView(ViewSettings, LocalizationManager.GetString("Settings_Title"), LocalizationManager.GetString("Settings_Subtitle"));
    }

    private void UpdateDevModeUI(bool isDevMode)
    {
        _isDeveloperMode = isDevMode;
        if (isDevMode)
        {
            TxtDevMode.Text = LocalizationManager.GetString("Status_DevMode");
            BadgeDevMode.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x26, 0xFF, 0xC8, 0x3B));
            BadgeDevMode.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x60, 0xFF, 0xC8, 0x3B));
            TxtDevMode.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xFF, 0xC8, 0x3B));

            if (TxtSettingsDevMode != null && BadgeSettingsDevMode != null)
            {
                TxtSettingsDevMode.Text = LocalizationManager.GetString("Status_Active");
                BadgeSettingsDevMode.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x26, 0xFF, 0xC8, 0x3B));
                BadgeSettingsDevMode.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x60, 0xFF, 0xC8, 0x3B));
                TxtSettingsDevMode.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xFF, 0xC8, 0x3B));
            }
        }
        else
        {
            TxtDevMode.Text = LocalizationManager.GetString("Status_StrictZeroTrust");
            BadgeDevMode.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x20, 0x06, 0xB6, 0xD4));
            BadgeDevMode.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x50, 0x06, 0xB6, 0xD4));
            TxtDevMode.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x06, 0xB6, 0xD4));

            if (TxtSettingsDevMode != null && BadgeSettingsDevMode != null)
            {
                TxtSettingsDevMode.Text = LocalizationManager.GetString("Status_Inactive");
                BadgeSettingsDevMode.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x18, 0xFF, 0xFF, 0xFF));
                BadgeSettingsDevMode.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x30, 0xFF, 0xFF, 0xFF));
                TxtSettingsDevMode.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x9E, 0x9E, 0x9E));
            }
        }
    }

    private void UpdateFirewallPolicyUI(bool isBlocked)
    {
        _isOutboundBlocked = isBlocked;

        if (isBlocked)
        {
            TxtCardOutbound.Text = LocalizationManager.GetString("Metric_FirewallBlocked");
            TxtCardOutbound.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 153, 164));

            TxtFirewallPolicyBadge.Text = LocalizationManager.GetString("Metric_FirewallBlocked");
            TxtFirewallPolicyBadge.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 153, 164));
            BadgeFirewallPolicy.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x26, 255, 153, 164));
            BadgeFirewallPolicy.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x60, 255, 153, 164));

            TxtFirewallPolicyDesc.Text = LocalizationManager.GetString("Firewall_PolicyDescBlock");
            BtnTogglePolicy.Content = LocalizationManager.GetString("Firewall_BtnAllowAll");
        }
        else
        {
            TxtCardOutbound.Text = LocalizationManager.GetString("Metric_FirewallAllowed");
            TxtCardOutbound.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(108, 203, 95));

            TxtFirewallPolicyBadge.Text = LocalizationManager.GetString("Metric_FirewallAllowed");
            TxtFirewallPolicyBadge.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(108, 203, 95));
            BadgeFirewallPolicy.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x20, 108, 203, 95));
            BadgeFirewallPolicy.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x50, 108, 203, 95));

            TxtFirewallPolicyDesc.Text = LocalizationManager.GetString("Firewall_PolicyDescAllow");
            BtnTogglePolicy.Content = LocalizationManager.GetString("Firewall_BtnBlockAll");
        }

        if (_currentTab == "Firewall" || _currentTab == "NetworkMonitor")
        {
            _ = RefreshNetworkConnectionsAsync();
        }
    }

    private async void BtnTogglePolicy_Click(object sender, RoutedEventArgs e)
    {
        bool targetBlock = !_isOutboundBlocked;

        if (!targetBlock)
        {
            var choice = MessageBox.Show(
                LocalizationManager.GetString("Msg_ConfirmPolicyAllow"),
                LocalizationManager.GetString("Msg_PolicyChangeTitle"),
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (choice != MessageBoxResult.Yes)
                return;
        }

        BtnTogglePolicy.IsEnabled = false;
        try
        {
            var resp = await _ipcClient.SetFirewallPolicyAsync(targetBlock);
            if (resp != null && resp.Success)
            {
                UpdateFirewallPolicyUI(resp.OutboundBlocked);
                MessageBox.Show(
                    targetBlock
                        ? LocalizationManager.GetString("Msg_PolicyBlockSwitched")
                        : LocalizationManager.GetString("Msg_PolicyAllowSwitched"),
                    LocalizationManager.GetString("Msg_PolicyChangeTitle"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show($"{LocalizationManager.GetString("Msg_ErrorTitle")}: {resp?.Message ?? "No response"}", LocalizationManager.GetString("Msg_ErrorTitle"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        finally
        {
            BtnTogglePolicy.IsEnabled = true;
        }
    }

    private void ShowView(UIElement view, string title, string subtitle)
    {
        if (ViewDashboard != null) ViewDashboard.Visibility = Visibility.Collapsed;
        if (ViewFirewall != null) ViewFirewall.Visibility = Visibility.Collapsed;
        if (ViewNetworkMonitor != null) ViewNetworkMonitor.Visibility = Visibility.Collapsed;
        if (ViewInjection != null) ViewInjection.Visibility = Visibility.Collapsed;
        if (ViewSettings != null) ViewSettings.Visibility = Visibility.Collapsed;
        if (ViewDpiBypass != null) ViewDpiBypass.Visibility = Visibility.Collapsed;
        if (ViewCloudTunnel != null) ViewCloudTunnel.Visibility = Visibility.Collapsed;

        if (view != null) view.Visibility = Visibility.Visible;
        if (TxtPageTitle != null) TxtPageTitle.Text = title;
        if (TxtPageSubtitle != null) TxtPageSubtitle.Text = subtitle;

        if (view == ViewNetworkMonitor)
        {
            BtnBackToFirewall.Visibility = Visibility.Visible;
            _netMonTimer.Start();
            _ = RefreshNetworkConnectionsAsync();
        }
        else
        {
            BtnBackToFirewall.Visibility = Visibility.Collapsed;
            if (view == ViewFirewall)
            {
                _netMonTimer.Start();
                _ = RefreshNetworkConnectionsAsync();
            }
            else
            {
                _netMonTimer.Stop();
            }
        }

        if (view == ViewDpiBypass)
        {
            if (_zapretEngine.IsRunning)
            {
                _dpiTelemetryTimer.Start();
            }
            UpdateDpiTelemetry();
        }
        else
        {
            _dpiTelemetryTimer.Stop();
        }
    }

    #region Network Monitor Handlers

    public void OpenNetworkMonitorSubpage()
    {
        _currentTab = "NetworkMonitor";
        ShowView(ViewNetworkMonitor, LocalizationManager.GetString("NetMon_Title"), LocalizationManager.GetString("NetMon_Subtitle"));
    }

    private void CardOpenNetworkMonitor_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        OpenNetworkMonitorSubpage();
    }

    private void BtnOpenNetMonSubpage_Click(object sender, RoutedEventArgs e)
    {
        OpenNetworkMonitorSubpage();
    }

    private void BtnBackToFirewall_Click(object sender, RoutedEventArgs e)
    {
        NavFirewall.IsChecked = true;
        NavFirewall_Click(sender, e);
    }

    private bool FilterConnections(object item)
    {
        if (item is not NetworkConnectionInfo conn) return false;

        // Protocol filter
        if (CmbProtocolFilter?.SelectedItem is ComboBoxItem selectedProtocol)
        {
            string tag = selectedProtocol.Tag?.ToString() ?? "ALL";
            if (tag == "TCP" && conn.Protocol != NetworkProtocol.Tcp) return false;
            if (tag == "UDP" && conn.Protocol != NetworkProtocol.Udp) return false;
        }

        // Status filter
        if (CmbStatusFilter?.SelectedItem is ComboBoxItem selectedStatus)
        {
            string sTag = selectedStatus.Tag?.ToString() ?? "ALL";
            if (sTag == "WHITELISTED" && conn.EnforcementStatus != ZeroTrustEnforcementStatus.Whitelisted) return false;
            if (sTag == "BLOCKED" && conn.EnforcementStatus != ZeroTrustEnforcementStatus.Blocked) return false;
            if (sTag == "EXCEPTION" && conn.EnforcementStatus != ZeroTrustEnforcementStatus.SystemException) return false;
        }

        // Search filter (ProcessName, PID, LocalEndpoint, RemoteEndpoint, State, ProcessPath)
        string search = TxtConnectionSearch?.Text?.Trim() ?? string.Empty;
        if (!string.IsNullOrEmpty(search))
        {
            bool match = conn.ProcessName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                         conn.ProcessId.ToString().Contains(search, StringComparison.OrdinalIgnoreCase) ||
                         conn.LocalEndpoint.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                         conn.RemoteEndpoint.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                         conn.State.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                         conn.ProcessPath.Contains(search, StringComparison.OrdinalIgnoreCase);

            if (!match) return false;
        }

        return true;
    }

    private void TxtConnectionSearch_TextChanged(object sender, TextChangedEventArgs e)
    {
        _connectionsView?.Refresh();
        UpdateConnectionsCountBadge();
    }

    private void CmbProtocolFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _connectionsView?.Refresh();
        UpdateConnectionsCountBadge();
    }

    private void CmbStatusFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _connectionsView?.Refresh();
        UpdateConnectionsCountBadge();
    }

    private void UpdateConnectionsCountBadge()
    {
        int count = _connectionsView?.Cast<object>().Count() ?? NetworkConnections.Count;
        string fmt = LocalizationManager.GetString("NetMon_CountFormat");
        string formattedCount = string.Format(fmt, count);

        if (TxtConnectionsCount != null)
        {
            TxtConnectionsCount.Text = formattedCount;
        }

        if (TxtFirewallSocketsCount != null)
        {
            TxtFirewallSocketsCount.Text = formattedCount;
        }

        int tcpCount = NetworkConnections.Count(c => c.Protocol == NetworkProtocol.Tcp);
        int udpCount = NetworkConnections.Count(c => c.Protocol == NetworkProtocol.Udp);
        int whitelistedCount = NetworkConnections.Count(c => c.EnforcementStatus == ZeroTrustEnforcementStatus.Whitelisted);
        int blockedCount = NetworkConnections.Count(c => c.EnforcementStatus == ZeroTrustEnforcementStatus.Blocked);
        int exceptionsCount = NetworkConnections.Count(c => c.EnforcementStatus == ZeroTrustEnforcementStatus.SystemException);

        if (TxtStatTcp != null) TxtStatTcp.Text = $"TCP: {tcpCount}";
        if (TxtStatUdp != null) TxtStatUdp.Text = $"UDP: {udpCount}";
        if (TxtStatWhitelisted != null) TxtStatWhitelisted.Text = $"Whitelisted: {whitelistedCount}";
        if (TxtStatBlocked != null) TxtStatBlocked.Text = $"Blocked: {blockedCount}";
        if (TxtStatExceptions != null) TxtStatExceptions.Text = $"System: {exceptionsCount}";
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

    private async Task RefreshNetworkConnectionsAsync()
    {
        try
        {
            var whitelistedPaths = WhitelistEntries
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
            UpdateConnectionsCountBadge();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[NetMon] Refresh error: {ex.Message}");
        }
    }

    #endregion

    private void BtnMinimizeToTray_Click(object sender, RoutedEventArgs e)
    {
        Hide();
        _notifyIcon?.ShowBalloonTip(
            2000, 
            LocalizationManager.GetString("Tray_MinimizedTitle"), 
            LocalizationManager.GetString("Tray_MinimizedMsg"), 
            ToolTipIcon.Info);
    }

    private void ShowAndActivate()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (!_reallyExit)
        {
            e.Cancel = true;
            Hide();
        }
        else
        {
            StopDpiBypass();
            SystemDnsManager.RestoreDns();
            _cloudTunnelManager.Stop();
            WindowsProxyManager.DisableProxy();
            _notifyIcon?.Dispose();
            _ipcClient.Dispose();
        }
    }

    private void TxtSearch_TextChanged(object sender, TextChangedEventArgs e)
    {
        var filter = TxtSearch.Text.Trim();
        _whitelistView.Filter = obj =>
        {
            if (string.IsNullOrEmpty(filter))
                return true;

            if (obj is WhitelistEntry entry)
            {
                return entry.FileName.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                       entry.FilePath.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                       entry.AppGroup.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                       (entry.SignerSubject?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false);
            }
            return true;
        };
    }

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    private const int DWMWA_SYSTEMBACKDROP_TYPE = 38;

    public static void ApplyWindows11Style(Window window)
    {
        try
        {
            var helper = new System.Windows.Interop.WindowInteropHelper(window);
            var hwnd = helper.Handle;
            if (hwnd == IntPtr.Zero) return;

            // 1. Dark Mode Title Bar
            int darkMode = 1;
            DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref darkMode, sizeof(int));

            // 2. Windows 11 Rounded Corners (2 = DWMWCP_ROUND)
            int cornerPref = 2;
            DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref cornerPref, sizeof(int));

            // 3. System Backdrop Mica
            int backdrop = 2;
            DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, ref backdrop, sizeof(int));
        }
        catch { }
    }

    #region DPI Bypass (Zapret Engine) & DoH Methods

    private void BtnToggleDpiBypass_Click(object sender, RoutedEventArgs e)
    {
        // If bypass is active, engine is running, or button is in Stop/Danger state -> user wants to stop
        if (_isDpiBypassActive || _zapretEngine.IsRunning || BtnToggleDpiBypass.Appearance == Wpf.Ui.Controls.ControlAppearance.Danger)
        {
            StopDpiBypass();
        }
        else
        {
            StartDpiBypass();
        }
    }

    private void StartDpiBypass()
    {
        try
        {
            var preset = CmbZapretPreset.SelectedItem as string ?? "General";
            _zapretEngine.Start(preset);

            if (ChkAutoConnectDns.IsChecked == true)
            {
                var preferredServer = DohServers.FirstOrDefault(s => s.IsActiveDns) 
                                   ?? DohServers.FirstOrDefault(s => s.Name.Contains("Cloudflare", StringComparison.OrdinalIgnoreCase))
                                   ?? DohServers.FirstOrDefault();

                if (preferredServer != null)
                {
                    SystemDnsManager.ConnectDns(preferredServer.Name, preferredServer.DirectIp, preferredServer.SecondaryIp, preferredServer.Url);
                    foreach (var s in DohServers)
                    {
                        s.IsActiveDns = (s == preferredServer);
                    }
                }
            }

            _isDpiBypassActive = true;
            _dpiTelemetryTimer?.Start();
            UpdateDpiTelemetry();
            UpdateDpiUiState(true);
        }
        catch (Exception ex)
        {
            _isDpiBypassActive = false;
            UpdateDpiUiState(false);
            UpdateDpiTelemetry();
            MessageBox.Show(
                $"Не удалось запустить службу обхода DPI (Zapret winws):\n\n{ex.Message}",
                LocalizationManager.GetString("DpiBypass_Title"),
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void StopDpiBypass()
    {
        try
        {
            _zapretEngine.Stop();

            if (SystemDnsManager.IsConnected)
            {
                SystemDnsManager.RestoreDns();
                foreach (var s in DohServers)
                {
                    s.IsActiveDns = false;
                }
            }
        }
        catch { }
        finally
        {
            _dpiTelemetryTimer?.Stop();
            _isDpiBypassActive = false;
            UpdateDpiTelemetry();
            UpdateDpiUiState(false);
        }
    }

    private void BtnConnectDohServer_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.FrameworkElement elem && elem.Tag is DohServerInfo server)
        {
            if (server.IsActiveDns)
            {
                SystemDnsManager.RestoreDns();
                server.IsActiveDns = false;
            }
            else
            {
                bool success = SystemDnsManager.ConnectDns(server.Name, server.DirectIp, server.SecondaryIp, server.Url);
                if (success)
                {
                    foreach (var s in DohServers)
                    {
                        s.IsActiveDns = (s == server);
                    }
                }
            }
            UpdateDpiTelemetry();
        }
    }

    private void CmbZapretPreset_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if ((_isDpiBypassActive || _zapretEngine.IsRunning) && CmbZapretPreset.SelectedItem is string)
        {
            // Restart with the newly selected preset
            StartDpiBypass();
        }
        else
        {
            UpdateDpiTelemetry();
        }
    }

    private async void BtnRefreshDohPing_Click(object sender, RoutedEventArgs e)
    {
        BtnRefreshDohPing.IsEnabled = false;
        try
        {
            await _dohPool.RunHealthChecksAsync();
            ItemsDohServers.Items.Refresh();
        }
        finally
        {
            BtnRefreshDohPing.IsEnabled = true;
        }
    }

    private void UpdateDpiTelemetry()
    {
        if (_zapretEngine.IsRunning)
        {
            TxtDpiActiveConn.Text = _zapretEngine.ProcessId.HasValue ? _zapretEngine.ProcessId.Value.ToString() : "АКТИВЕН";
            TxtDpiBytes.Text = _zapretEngine.CurrentPreset;
            TxtDpiDnsHits.Text = SystemDnsManager.IsConnected
                ? (SystemDnsManager.ActiveProviderName ?? "DoH")
                : "WinDivert L3/L4";
        }
        else
        {
            // If the UI was marked active but the process terminated externally, resync UI state
            if (_isDpiBypassActive)
            {
                _isDpiBypassActive = false;
                UpdateDpiUiState(false);
            }

            TxtDpiActiveConn.Text = "—";
            TxtDpiBytes.Text = CmbZapretPreset?.SelectedItem as string ?? "General";
            TxtDpiDnsHits.Text = SystemDnsManager.IsConnected
                ? (SystemDnsManager.ActiveProviderName ?? "DoH")
                : "Остановлен";
        }
    }

    private void UpdateDpiUiState(bool isRunning)
    {
        if (isRunning)
        {
            BadgeDpiStatus.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x20, 108, 203, 95));
            BadgeDpiStatus.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x50, 108, 203, 95));
            TxtDpiStatus.Text = LocalizationManager.GetString("DpiBypass_StatusActive");
            TxtDpiStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(108, 203, 95));

            BtnToggleDpiBypass.Content = LocalizationManager.GetString("DpiBypass_BtnDisable");
            BtnToggleDpiBypass.Appearance = Wpf.Ui.Controls.ControlAppearance.Danger;
            BtnToggleDpiBypass.Icon = new Wpf.Ui.Controls.SymbolIcon { Symbol = Wpf.Ui.Controls.SymbolRegular.Stop24 };
        }
        else
        {
            BadgeDpiStatus.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x20, 136, 136, 136));
            BadgeDpiStatus.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(0x50, 136, 136, 136));
            TxtDpiStatus.Text = LocalizationManager.GetString("DpiBypass_StatusInactive");
            TxtDpiStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(160, 160, 160));

            BtnToggleDpiBypass.Content = LocalizationManager.GetString("DpiBypass_BtnEnable");
            BtnToggleDpiBypass.Appearance = Wpf.Ui.Controls.ControlAppearance.Primary;
            BtnToggleDpiBypass.Icon = new Wpf.Ui.Controls.SymbolIcon { Symbol = Wpf.Ui.Controls.SymbolRegular.Play24 };
        }
    }

    #region Custom Domain Lists Editor Handlers

    private void LoadDomainList(string listFileName)
    {
        _activeSelectedList = listFileName;

        // Update tab button styles
        BtnTabGeneralList.Appearance = (listFileName == DomainListManager.ListGeneral) ? ControlAppearance.Primary : ControlAppearance.Secondary;
        BtnTabGoogleList.Appearance = (listFileName == DomainListManager.ListGoogle) ? ControlAppearance.Primary : ControlAppearance.Secondary;
        BtnTabExcludeList.Appearance = (listFileName == DomainListManager.ListExclude) ? ControlAppearance.Primary : ControlAppearance.Secondary;

        var domains = _domainListManager.LoadList(listFileName);
        _allDomainsForCurrentList.Clear();
        foreach (var d in domains)
        {
            _allDomainsForCurrentList.Add(d);
        }

        if (TxtDomainsRawNotepad != null)
        {
            _suppressNotepadTextSync = true;
            TxtDomainsRawNotepad.Text = string.Join(Environment.NewLine, _allDomainsForCurrentList);
            _suppressNotepadTextSync = false;
        }

        ApplyDomainFilter(TxtSearchDomains?.Text);
    }

    private void SetViewMode(bool isNotepad)
    {
        _isNotepadViewMode = isNotepad;

        if (_isNotepadViewMode)
        {
            BtnViewModeItems.Appearance = ControlAppearance.Secondary;
            BtnViewModeNotepad.Appearance = ControlAppearance.Primary;

            PanelItemsView.Visibility = Visibility.Collapsed;
            PanelNotepadView.Visibility = Visibility.Visible;
            TxtSearchDomains.Visibility = Visibility.Collapsed;

            _suppressNotepadTextSync = true;
            TxtDomainsRawNotepad.Text = string.Join(Environment.NewLine, _allDomainsForCurrentList);
            _suppressNotepadTextSync = false;
        }
        else
        {
            BtnViewModeItems.Appearance = ControlAppearance.Primary;
            BtnViewModeNotepad.Appearance = ControlAppearance.Secondary;

            PanelItemsView.Visibility = Visibility.Visible;
            PanelNotepadView.Visibility = Visibility.Collapsed;
            TxtSearchDomains.Visibility = Visibility.Visible;

            SyncFromNotepadText();
        }
    }

    private void SyncFromNotepadText()
    {
        if (TxtDomainsRawNotepad == null) return;
        var parsed = DomainListManager.ParseRawText(TxtDomainsRawNotepad.Text);
        _allDomainsForCurrentList.Clear();
        foreach (var d in parsed)
        {
            _allDomainsForCurrentList.Add(d);
        }
        ApplyDomainFilter(TxtSearchDomains?.Text);
    }

    private void BtnViewMode_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is string mode)
        {
            SetViewMode(mode == "Notepad");
        }
    }

    private void TxtDomainsRawNotepad_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_suppressNotepadTextSync) return;
        var lines = TxtDomainsRawNotepad.Text.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        int count = lines.Count(l => !string.IsNullOrWhiteSpace(l) && !l.TrimStart().StartsWith('#') && !l.TrimStart().StartsWith(';'));
        if (TxtDomainCountBadge != null)
        {
            TxtDomainCountBadge.Text = count.ToString();
        }
    }

    private void BtnOpenSystemNotepad_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_isNotepadViewMode)
            {
                SyncFromNotepadText();
            }
            _domainListManager.SaveList(_activeSelectedList, _allDomainsForCurrentList);
            _domainListManager.OpenInSystemEditor(_activeSelectedList);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Failed to open in Notepad: {ex.Message}",
                LocalizationManager.GetString("DpiBypass_ListsTitle"),
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private void ApplyDomainFilter(string? query)
    {
        _filteredDomains.Clear();
        var q = query?.Trim();

        if (string.IsNullOrEmpty(q))
        {
            foreach (var d in _allDomainsForCurrentList)
            {
                _filteredDomains.Add(d);
            }
        }
        else
        {
            foreach (var d in _allDomainsForCurrentList)
            {
                if (d.Contains(q, StringComparison.OrdinalIgnoreCase))
                {
                    _filteredDomains.Add(d);
                }
            }
        }

        if (TxtDomainCountBadge != null)
        {
            TxtDomainCountBadge.Text = _allDomainsForCurrentList.Count.ToString();
        }

        if (TxtEmptyDomainsState != null)
        {
            TxtEmptyDomainsState.Visibility = _filteredDomains.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private void TxtSearchDomains_TextChanged(object sender, TextChangedEventArgs e)
    {
        ApplyDomainFilter(TxtSearchDomains.Text);
    }

    private void BtnTabList_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is string listName)
        {
            if (_isNotepadViewMode)
            {
                SyncFromNotepadText();
                _domainListManager.SaveList(_activeSelectedList, _allDomainsForCurrentList);
            }
            LoadDomainList(listName);
        }
    }

    private void BtnAddNewDomain_Click(object sender, RoutedEventArgs e)
    {
        AddCurrentDomainInput();
    }

    private void TxtNewDomain_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Enter)
        {
            AddCurrentDomainInput();
            e.Handled = true;
        }
    }

    private void AddCurrentDomainInput()
    {
        var rawInput = TxtNewDomain.Text?.Trim();
        if (string.IsNullOrWhiteSpace(rawInput))
        {
            return;
        }

        if (!DomainListManager.TrySanitizeDomain(rawInput, out var cleanDomain, out var error))
        {
            MessageBox.Show(
                $"{LocalizationManager.GetString("DpiBypass_MsgInvalidDomain")}\n{error}",
                LocalizationManager.GetString("DpiBypass_ListsTitle"),
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        if (_allDomainsForCurrentList.Any(d => string.Equals(d, cleanDomain, StringComparison.OrdinalIgnoreCase)))
        {
            MessageBox.Show(
                LocalizationManager.GetString("DpiBypass_MsgDomainExists"),
                LocalizationManager.GetString("DpiBypass_ListsTitle"),
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        _allDomainsForCurrentList.Add(cleanDomain);
        var sorted = _allDomainsForCurrentList.OrderBy(d => d, StringComparer.OrdinalIgnoreCase).ToList();
        _allDomainsForCurrentList.Clear();
        foreach (var d in sorted)
        {
            _allDomainsForCurrentList.Add(d);
        }

        TxtNewDomain.Clear();
        _domainListManager.SaveList(_activeSelectedList, _allDomainsForCurrentList);
        if (TxtDomainsRawNotepad != null && !_isNotepadViewMode)
        {
            _suppressNotepadTextSync = true;
            TxtDomainsRawNotepad.Text = string.Join(Environment.NewLine, _allDomainsForCurrentList);
            _suppressNotepadTextSync = false;
        }
        ApplyDomainFilter(TxtSearchDomains.Text);
    }

    private void BtnDeleteDomain_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is string domain)
        {
            var itemToRemove = _allDomainsForCurrentList.FirstOrDefault(d => string.Equals(d, domain, StringComparison.OrdinalIgnoreCase));
            if (itemToRemove != null)
            {
                _allDomainsForCurrentList.Remove(itemToRemove);
                _domainListManager.SaveList(_activeSelectedList, _allDomainsForCurrentList);
                if (TxtDomainsRawNotepad != null && !_isNotepadViewMode)
                {
                    _suppressNotepadTextSync = true;
                    TxtDomainsRawNotepad.Text = string.Join(Environment.NewLine, _allDomainsForCurrentList);
                    _suppressNotepadTextSync = false;
                }
                ApplyDomainFilter(TxtSearchDomains.Text);
            }
        }
    }

    private void BtnApplyDomainLists_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_isNotepadViewMode)
            {
                SyncFromNotepadText();
                _suppressNotepadTextSync = true;
                TxtDomainsRawNotepad.Text = string.Join(Environment.NewLine, _allDomainsForCurrentList);
                _suppressNotepadTextSync = false;
            }

            _domainListManager.SaveList(_activeSelectedList, _allDomainsForCurrentList);
            if (_zapretEngine.IsRunning)
            {
                _zapretEngine.Restart();
                UpdateDpiTelemetry();
            }

            MessageBox.Show(
                LocalizationManager.GetString("DpiBypass_MsgListsApplied"),
                LocalizationManager.GetString("DpiBypass_ListsTitle"),
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Error saving lists: {ex.Message}",
                LocalizationManager.GetString("DpiBypass_ListsTitle"),
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void BtnImportDomainList_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var ofd = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Import Domain List",
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
            };

            if (ofd.ShowDialog() == true)
            {
                int added = _domainListManager.ImportList(_activeSelectedList, ofd.FileName, mergeWithExisting: true);
                LoadDomainList(_activeSelectedList);

                if (_zapretEngine.IsRunning)
                {
                    _zapretEngine.Restart();
                    UpdateDpiTelemetry();
                }

                MessageBox.Show(
                    $"Imported {added} new domains into {_activeSelectedList}.",
                    LocalizationManager.GetString("DpiBypass_ListsTitle"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Import failed: {ex.Message}",
                LocalizationManager.GetString("DpiBypass_ListsTitle"),
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void BtnExportDomainList_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var sfd = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export Domain List",
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                FileName = _activeSelectedList
            };

            if (sfd.ShowDialog() == true)
            {
                _domainListManager.ExportList(_activeSelectedList, sfd.FileName);
                MessageBox.Show(
                    $"List {_activeSelectedList} exported successfully.",
                    LocalizationManager.GetString("DpiBypass_ListsTitle"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Export failed: {ex.Message}",
                LocalizationManager.GetString("DpiBypass_ListsTitle"),
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private async void BtnFetchCommunityList_Click(object sender, RoutedEventArgs e)
    {
        BtnFetchCommunityList.IsEnabled = false;
        try
        {
            var url = $"https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/zapret-discord-youtube-1.10.2/lists/{_activeSelectedList}";
            var (added, total) = await _domainListManager.FetchCommunityListAsync(_activeSelectedList, url);
            LoadDomainList(_activeSelectedList);

            if (_zapretEngine.IsRunning)
            {
                _zapretEngine.Restart();
                UpdateDpiTelemetry();
            }

            MessageBox.Show(
                $"Online update completed: added {added} new domains (total: {total}).",
                LocalizationManager.GetString("DpiBypass_ListsTitle"),
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Online fetch error: {ex.Message}",
                LocalizationManager.GetString("DpiBypass_ListsTitle"),
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            BtnFetchCommunityList.IsEnabled = true;
        }
    }

    #endregion

    #region Cloud Tunnel & TG WS Proxy Handlers

    private void UpdateCloudTunnelUI()
    {
        if (TxtCloudTunnelStatus == null) return;

        bool isRunning = _cloudTunnelManager.IsRunning;
        if (isRunning)
        {
            TxtCloudTunnelStatus.Text = LocalizationManager.GetString("CloudTunnel_StatusActive");
            TxtCloudTunnelStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x4C, 0xC2, 0xFF));
            BtnToggleCloudTunnel.Content = LocalizationManager.GetString("CloudTunnel_BtnDisable");
            BtnToggleCloudTunnel.Appearance = Wpf.Ui.Controls.ControlAppearance.Danger;
        }
        else
        {
            TxtCloudTunnelStatus.Text = LocalizationManager.GetString("CloudTunnel_StatusStopped");
            TxtCloudTunnelStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xE0, 0x52, 0x52));
            BtnToggleCloudTunnel.Content = LocalizationManager.GetString("CloudTunnel_BtnEnable");
            BtnToggleCloudTunnel.Appearance = Wpf.Ui.Controls.ControlAppearance.Success;
        }

        if (_cloudTunnelManager.WorkerPingMs >= 0)
        {
            TxtCloudTunnelPing.Text = $"{_cloudTunnelManager.WorkerPingMs} мс";
            TxtCloudTunnelPing.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x4C, 0xC2, 0xFF));
        }
        else
        {
            TxtCloudTunnelPing.Text = "—";
            TxtCloudTunnelPing.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x88, 0x88, 0x88));
        }

        TxtCloudTunnelTraffic.Text = $"{FormatBytes(_cloudTunnelManager.BytesUploaded)} / {FormatBytes(_cloudTunnelManager.BytesDownloaded)}";
        TxtCloudTunnelSessions.Text = $"{_cloudTunnelManager.ActiveConnections} активных сессий";

        TxtTgHostPort.Text = $"{_cloudTunnelManager.Config.Host}:{_cloudTunnelManager.Config.MtprotoPort}";
        TxtTgSecret.Text = _cloudTunnelManager.Config.Secret;
        ChkSystemProxy.IsChecked = WindowsProxyManager.IsProxyEnabled();
        ChkBypassRu.IsChecked = _cloudTunnelManager.Config.BypassRussianTraffic;

        if (!TxtWorkerDomains.IsFocused && _cloudTunnelManager.Config.WorkerDomains.Count > 0)
        {
            var expected = string.Join(", ", _cloudTunnelManager.Config.WorkerDomains);
            if (string.IsNullOrWhiteSpace(TxtWorkerDomains.Text) || TxtWorkerDomains.Text != expected)
            {
                TxtWorkerDomains.Text = expected;
            }
        }
    }

    private List<string> SaveWorkerDomainsFromInput()
    {
        var raw = TxtWorkerDomains.Text;
        var domains = raw.Split(new[] { ',', ';', ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                         .Select(d => d.Trim().Replace("https://", "").Replace("http://", "").TrimEnd('/'))
                         .Where(d => !string.IsNullOrWhiteSpace(d))
                         .Distinct(StringComparer.OrdinalIgnoreCase)
                         .ToList();

        _cloudTunnelManager.Config.WorkerDomains = domains;
        _cloudTunnelManager.Config.Save();
        return domains;
    }

    private void BtnToggleCloudTunnel_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_cloudTunnelManager.IsRunning)
            {
                _cloudTunnelManager.Stop();
            }
            else
            {
                if (_cloudTunnelManager.Config.WorkerDomains.Count == 0 && !string.IsNullOrWhiteSpace(TxtWorkerDomains?.Text))
                {
                    SaveWorkerDomainsFromInput();
                }
                _cloudTunnelManager.Start();
            }
            _cloudTunnelManager.Config.IsEnabled = _cloudTunnelManager.IsRunning;
            _cloudTunnelManager.Config.Save();
            UpdateCloudTunnelUI();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Ошибка переключения туннеля: {ex.Message}", "OmniEye Cloud Tunnel", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void BtnConnectTelegram_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_cloudTunnelManager.Config.WorkerDomains.Count == 0 && !string.IsNullOrWhiteSpace(TxtWorkerDomains?.Text))
            {
                SaveWorkerDomainsFromInput();
            }

            if (!_cloudTunnelManager.IsRunning)
            {
                _cloudTunnelManager.Start();
                _cloudTunnelManager.Config.IsEnabled = true;
                _cloudTunnelManager.Config.Save();
                UpdateCloudTunnelUI();
            }

            var link = _cloudTunnelManager.Config.GetTelegramLink();
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(link) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Не удалось открыть Telegram: {ex.Message}\nСсылка скопирована в буфер обмена.", "OmniEye", MessageBoxButton.OK, MessageBoxImage.Information);
            try { System.Windows.Clipboard.SetText(_cloudTunnelManager.Config.GetTelegramLink()); } catch { }
        }
    }

    private void BtnCopyTgLink_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.Windows.Clipboard.SetText(_cloudTunnelManager.Config.GetTelegramLink());
            BtnCopyTgLink.Content = "✓ Скопировано";
            _ = Task.Delay(2000).ContinueWith(_ => Dispatcher.Invoke(() => BtnCopyTgLink.Content = LocalizationManager.GetString("CloudTunnel_BtnCopyTgLink")));
        }
        catch { }
    }

    private void BtnRegenerateSecret_Click(object sender, RoutedEventArgs e)
    {
        _cloudTunnelManager.Config.Secret = CloudTunnelConfig.GenerateSecret();
        _cloudTunnelManager.Config.Save();
        if (_cloudTunnelManager.IsRunning)
        {
            _cloudTunnelManager.UpdateConfig(_cloudTunnelManager.Config);
        }
        UpdateCloudTunnelUI();
    }

    private void ChkSystemProxy_Click(object sender, RoutedEventArgs e)
    {
        bool enable = ChkSystemProxy.IsChecked == true;
        _cloudTunnelManager.Config.EnableSystemProxy = enable;
        _cloudTunnelManager.Config.Save();
        if (enable)
        {
            WindowsProxyManager.EnableProxy(_cloudTunnelManager.Config.Host, _cloudTunnelManager.Config.Socks5Port, _cloudTunnelManager.Config.BypassRussianTraffic);
        }
        else
        {
            WindowsProxyManager.DisableProxy();
        }
        UpdateCloudTunnelUI();
    }

    private void ChkBypassRu_Click(object sender, RoutedEventArgs e)
    {
        _cloudTunnelManager.Config.BypassRussianTraffic = ChkBypassRu.IsChecked == true;
        _cloudTunnelManager.Config.Save();
        if (WindowsProxyManager.IsProxyEnabled())
        {
            WindowsProxyManager.EnableProxy(_cloudTunnelManager.Config.Host, _cloudTunnelManager.Config.Socks5Port, _cloudTunnelManager.Config.BypassRussianTraffic);
        }
    }

    private void BtnCopyTerminal_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string cmd = $"$env:HTTPS_PROXY=\"http://{_cloudTunnelManager.Config.Host}:{_cloudTunnelManager.Config.Socks5Port}\"; $env:HTTP_PROXY=\"http://{_cloudTunnelManager.Config.Host}:{_cloudTunnelManager.Config.Socks5Port}\"";
            System.Windows.Clipboard.SetText(cmd);
            BtnCopyTerminal.Content = "✓ Команда скопирована";
            _ = Task.Delay(2000).ContinueWith(_ => Dispatcher.Invoke(() => BtnCopyTerminal.Content = LocalizationManager.GetString("CloudTunnel_BtnCopyTerminal")));
        }
        catch { }
    }

    private async void BtnSaveWorkers_Click(object sender, RoutedEventArgs e)
    {
        SaveWorkerDomainsFromInput();

        if (_cloudTunnelManager.IsRunning)
        {
            _cloudTunnelManager.UpdateConfig(_cloudTunnelManager.Config);
        }

        BtnSaveWorkers.IsEnabled = false;
        BtnSaveWorkers.Content = "Проверка...";

        long ping = await _cloudTunnelManager.PingWorkerAsync();
        UpdateCloudTunnelUI();

        if (ping >= 0)
        {
            BtnSaveWorkers.Content = $"✓ Воркер отвечает ({ping} мс)";
        }
        else
        {
            BtnSaveWorkers.Content = "✓ Сохранено";
        }

        _ = Task.Delay(2500).ContinueWith(_ => Dispatcher.Invoke(() =>
        {
            BtnSaveWorkers.IsEnabled = true;
            BtnSaveWorkers.Content = LocalizationManager.GetString("CloudTunnel_BtnSave") ?? "Сохранить";
        }));
    }

    private void BtnWorkerScript_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.Windows.Clipboard.SetText(WorkerScript.Code);
            MessageBox.Show(
                WorkerScript.InstructionsRu + "\n\nКод скрипта worker.js скопирован в буфер обмена!",
                "Инструкция по Cloudflare Worker",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );
        }
        catch { }
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F1} MB";
        return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
    }

    #endregion

    #endregion
}