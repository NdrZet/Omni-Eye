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
using OmniEyeTray.Views;
using MessageBox = System.Windows.MessageBox;

namespace OmniEyeTray;

public partial class MainWindow : Window
{
    private readonly IpcClient _ipcClient;
    private NotifyIcon? _notifyIcon;
    private bool _isDeveloperMode = true;
    private bool _reallyExit = false;
    private readonly ICollectionView _whitelistView;

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

        SourceInitialized += (s, e) => ApplyWindows11Style(this);
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
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
        contextMenu.Items.Add("Открыть Dashboard", null, (s, e) => ShowAndActivate());
        contextMenu.Items.Add(new ToolStripSeparator());
        contextMenu.Items.Add("Выход", null, (s, e) =>
        {
            _reallyExit = true;
            Close();
        });

        _notifyIcon.ContextMenuStrip = contextMenu;
        _notifyIcon.DoubleClick += (s, e) => ShowAndActivate();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        await ConnectAndRefreshAsync();
    }

    private async Task ConnectAndRefreshAsync()
    {
        TxtServiceStatus.Text = "ПОДКЛЮЧЕНИЕ К СЛУЖБЕ...";
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
            TxtServiceStatus.Text = "СЛУЖБА НЕ ЗАПУЩЕНА (OFFLINE)";
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
                TxtServiceStatus.Text = "СЛУЖБА ПОДКЛЮЧЕНА";
                BadgeStatus.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(19, 56, 33));
                BadgeStatus.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(30, 97, 53));
                TxtServiceStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(108, 203, 95));
            }
            else
            {
                TxtServiceStatus.Text = "СЛУЖБА ОТКЛЮЧЕНА";
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
                "OmniEye: Попытка внедрения кода!",
                $"Процесс PID {notification.SourcePid} пытается внедриться в {Path.GetFileName(notification.TargetPath)}",
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
            TxtDevMode.Text = status.DeveloperMode ? "DEVELOPER MODE" : "STRICT ZERO-TRUST";
            TxtCardOutbound.Text = status.OutboundBlocked ? "БЛОКИРОВАН (BLOCK)" : "РАЗРЕШЕН (ALLOW)";
            TxtCardAttempts.Text = $"{status.BlockedAttemptsCount} попыток заблокировано";
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
            TxtCardWhitelistCount.Text = $"{groupCount} групп ({WhitelistEntries.Count} файлов)";
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
            Title = "Выберите исполняемый файл для Белого списка",
            Filter = "Исполняемые файлы (*.exe)|*.exe|Все файлы (*.*)|*.*"
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
                        $"Успешно добавлено {addedCount} компонентов приложения «{appName}» (включая службы и туннели) в Белый список и Firewall!",
                        "Группа успешно добавлена",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show(
                        $"Добавлено компонентов: {addedCount}.\nОшибки:\n{errors}",
                        "Результат добавления",
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
                    $"Файл не имеет валидной цифровой подписи Authenticode ({sig.StatusMessage}).\n\nВ режиме Strict Zero-Trust добавление неподписанных файлов запрещено!",
                    "Ошибка безопасности",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                return;
            }
            else
            {
                var choice = MessageBox.Show(
                    $"Файл не имеет доверенной цифровой подписи Authenticode ({sig.StatusMessage}).\n\nВключен Developer Mode. Вы уверены, что хотите добавить этот файл в Белый список?",
                    "Подтверждение (Developer Mode)",
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
                $"Файл успешно проверен:\nИздатель: {sig.SignerSubject}\nСертификат валиден.\n\nДобавить в Белый список?",
                "Проверка подписи пройдена",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);

            if (choice != MessageBoxResult.Yes)
                return;
        }

        var singleResp = await _ipcClient.AddToWhitelistAsync(primaryFilePath, bypassSignature);
        if (singleResp != null && singleResp.Success)
        {
            MessageBox.Show("Приложение успешно добавлено в Белый список и Firewall!", "Успешно", MessageBoxButton.OK, MessageBoxImage.Information);
            await RefreshDataAsync();
        }
        else
        {
            MessageBox.Show($"Не удалось добавить файл: {singleResp?.Message ?? "Нет ответа от службы"}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
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
                Role = role + (isAlreadyAdded ? " (Уже в списке)" : ""),
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
            return "Основное приложение";

        var lower = fileName.ToLowerInvariant();
        if (lower.Contains("service"))
            return "Фоновая служба";
        if (lower.Contains("tun") || lower.Contains("vpn") || lower.Contains("wireguard") || lower.Contains("openvpn") || lower.Contains("proxy"))
            return "Сетевой туннель / VPN";
        if (lower.Contains("update") || lower.Contains("upgrade") || lower.Contains("installer"))
            return "Служба обновления";
        if (lower.Contains("helper") || lower.Contains("crash") || lower.Contains("reporter"))
            return "Вспомогательный процесс";
        if (lower.Contains("unins") || lower.Contains("maintenancetool"))
            return "Деинсталлятор";

        return "Сопутствующий компонент";
    }

    private void BtnRemove_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show("Для удаления приложения нажмите кнопку «✕» напротив нужного файла или кнопку «Удалить группу» в заголовке карточки приложения.", "Удаление", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async void BtnDeleteGroup_Click(object sender, RoutedEventArgs e)
    {
        e.Handled = true;
        if (sender is System.Windows.Controls.Button btn && btn.DataContext is CollectionViewGroup group)
        {
            var entries = group.Items.OfType<WhitelistEntry>().ToList();
            if (entries.Count == 0) return;

            var choice = MessageBox.Show(
                $"Удалить всю группу «{group.Name}» ({entries.Count} файлов) из Белого списка?\nИсходящие сетевые соединения для них будут заблокированы.",
                "Удаление группы приложений",
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
                $"Удалить {entry.FileName} из Белого списка?\nИсходящие сетевые соединения для него будут заблокированы.",
                "Подтверждение удаления",
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
                    MessageBox.Show($"Ошибка при удалении: {resp?.Message ?? "Нет ответа"}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }
    }

    private void NavDashboard_Click(object sender, RoutedEventArgs e)
    {
        ShowView(ViewDashboard, "Главная", "Мониторинг исходящего сетевого трафика и изоляция процессов");
    }

    private void NavFirewall_Click(object sender, RoutedEventArgs e)
    {
        ShowView(ViewFirewall, "Сетевой экран", "Параметры и правила блокировки Windows Defender Firewall");
    }

    private void NavInjection_Click(object sender, RoutedEventArgs e)
    {
        ShowView(ViewInjection, "Защита ядра", "Мониторинг инъекций через ETW и заморозка NtSuspendProcess");
    }

    private void NavSettings_Click(object sender, RoutedEventArgs e)
    {
        ShowView(ViewSettings, "Параметры", "Режимы работы, шифрование базы данных и IPC");
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
        _notifyIcon?.ShowBalloonTip(2000, "OmniEye", "Приложение свернуто в трей и продолжает защиту.", ToolTipIcon.Info);
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