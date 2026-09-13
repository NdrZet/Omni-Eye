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
    private bool _isDeveloperMode = true;
    private bool _isOutboundBlocked = true;
    private bool _reallyExit = false;
    private readonly ICollectionView _whitelistView;
    private string _currentTab = "Dashboard";
    private int _lastBlockedAttempts = 0;

    public ObservableCollection<WhitelistEntry> WhitelistEntries { get; set; } = new();

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

        InitializeTrayIcon();

        // Language selector
        CmbLanguage.ItemsSource = LocalizationManager.SupportedLanguages;
        CmbLanguage.SelectedValue = LocalizationManager.CurrentLanguage;
        LocalizationManager.LanguageChanged += OnLanguageChanged;

        SourceInitialized += (s, e) => ApplyWindows11Style(this);
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
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
                case "Injection":
                    TxtPageTitle.Text = LocalizationManager.GetString("Injection_Title");
                    TxtPageSubtitle.Text = LocalizationManager.GetString("Injection_Subtitle");
                    break;
                case "Settings":
                    TxtPageTitle.Text = LocalizationManager.GetString("Settings_Title");
                    TxtPageSubtitle.Text = LocalizationManager.GetString("Settings_Subtitle");
                    break;
            }

            TxtDevMode.Text = _isDeveloperMode
                ? LocalizationManager.GetString("Status_DevMode")
                : LocalizationManager.GetString("Status_StrictZeroTrust");

            if (_ipcClient.IsConnected)
            {
                TxtServiceStatus.Text = LocalizationManager.GetString("Status_ServiceConnected");
            }
            else
            {
                TxtServiceStatus.Text = LocalizationManager.GetString("Status_ServiceOffline");
            }

            UpdateFirewallPolicyUI(_isOutboundBlocked);

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
        _notifyIcon = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
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
            _isDeveloperMode = status.DeveloperMode;
            _lastBlockedAttempts = status.BlockedAttemptsCount;
            TxtDevMode.Text = status.DeveloperMode 
                ? LocalizationManager.GetString("Status_DevMode") 
                : LocalizationManager.GetString("Status_StrictZeroTrust");
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

        var primaryFilePath = dialog.FileName;
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
        ViewDashboard.Visibility = Visibility.Collapsed;
        ViewFirewall.Visibility = Visibility.Collapsed;
        ViewInjection.Visibility = Visibility.Collapsed;
        ViewSettings.Visibility = Visibility.Collapsed;

        view.Visibility = Visibility.Visible;
        TxtPageTitle.Text = title;
        TxtPageSubtitle.Text = subtitle;
    }

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
}