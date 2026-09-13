using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
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
        DgWhitelist.ItemsSource = _whitelistView;

        InitializeTrayIcon();

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
        BadgeStatus.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(38, 30, 14));
        BadgeStatus.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(245, 158, 11));

        bool connected = await _ipcClient.ConnectAsync();
        if (connected)
        {
            await RefreshDataAsync();
        }
        else
        {
            TxtServiceStatus.Text = "СЛУЖБА НЕ ЗАПУЩЕНА (OFFLINE)";
            BadgeStatus.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(50, 18, 24));
            BadgeStatus.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(239, 68, 68));
            TxtServiceStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(248, 113, 113));
        }
    }

    private void OnConnectionChanged(bool isConnected)
    {
        Dispatcher.Invoke(() =>
        {
            if (isConnected)
            {
                TxtServiceStatus.Text = "СЛУЖБА ПОДКЛЮЧЕНА";
                BadgeStatus.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(12, 37, 24));
                BadgeStatus.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(16, 185, 129));
                TxtServiceStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(52, 211, 153));
            }
            else
            {
                TxtServiceStatus.Text = "СЛУЖБА ОТКЛЮЧЕНА";
                BadgeStatus.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(50, 18, 24));
                BadgeStatus.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(239, 68, 68));
                TxtServiceStatus.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(248, 113, 113));
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

    private async void BtnRemove_Click(object sender, RoutedEventArgs e)
    {
        if (DgWhitelist.SelectedItem is WhitelistEntry selected)
        {
            var choice = MessageBox.Show(
                $"Удалить {selected.FileName} из Белого списка?\nИсходящие соединения для него будут заблокированы.",
                "Подтверждение удаления",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (choice == MessageBoxResult.Yes)
            {
                var resp = await _ipcClient.RemoveFromWhitelistAsync(selected.Id);
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
        else
        {
            MessageBox.Show("Выберите приложение из таблицы для удаления.", "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
        }
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
}