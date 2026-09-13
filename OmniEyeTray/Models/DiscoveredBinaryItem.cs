using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace OmniEyeTray.Models;

public class DiscoveredBinaryItem : INotifyPropertyChanged
{
    private bool _isSelected;

    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string Role { get; set; } = "Компонент";
    public bool IsSigned { get; set; }
    public string? SignerSubject { get; set; }
    public bool IsAlreadyWhitelisted { get; set; }

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected != value)
            {
                _isSelected = value;
                OnPropertyChanged();
            }
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
