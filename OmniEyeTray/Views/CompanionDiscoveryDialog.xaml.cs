using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using OmniEyeTray.Models;
using OmniEyeTray.Services;

namespace OmniEyeTray.Views;

public partial class CompanionDiscoveryDialog : Window
{
    public ObservableCollection<DiscoveredBinaryItem> Components { get; } = new();

    public List<DiscoveredBinaryItem> SelectedItems => Components.Where(x => x.IsSelected).ToList();

    public CompanionDiscoveryDialog(string appName, IEnumerable<DiscoveredBinaryItem> discoveredItems)
    {
        InitializeComponent();
        SourceInitialized += (s, e) => MainWindow.ApplyWindows11Style(this);

        TxtSubtitle.Text = $"{appName} — {LocalizationManager.GetString("Comp_Subtitle")}";

        foreach (var item in discoveredItems)
        {
            item.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(DiscoveredBinaryItem.IsSelected))
                {
                    UpdateSelectionCount();
                }
            };
            Components.Add(item);
        }

        DgComponents.ItemsSource = Components;
        UpdateSelectionCount();
    }

    private void UpdateSelectionCount()
    {
        int count = Components.Count(x => x.IsSelected);
        TxtSelectionCount.Text = LocalizationManager.GetString("Comp_SelectionFormat", count);
        BtnConfirm.Content = $"{LocalizationManager.GetString("Comp_Confirm")} ({count})";
        BtnConfirm.IsEnabled = count > 0;
    }

    private void BtnSelectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var item in Components)
        {
            item.IsSelected = true;
        }
    }

    private void BtnUnselectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var item in Components)
        {
            item.IsSelected = false;
        }
    }

    private void BtnConfirm_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void BtnCancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
