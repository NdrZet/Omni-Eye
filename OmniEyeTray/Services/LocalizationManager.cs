using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Windows;

namespace OmniEyeTray.Services;

public record LanguageItem(string Code, string DisplayName);

public static class LocalizationManager
{
    public const string DefaultLanguage = "en-US";

    public static readonly IReadOnlyList<LanguageItem> SupportedLanguages = new List<LanguageItem>
    {
        new("en-US", "English"),
        new("ru-RU", "Русский"),
        new("uk-UA", "Українська"),
        new("de-DE", "Deutsch"),
        new("ja-JP", "日本語")
    };

    public static string CurrentLanguage { get; private set; } = DefaultLanguage;

    public static event Action? LanguageChanged;

    private static readonly string SettingsFilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "OmniEye",
        "ui_settings.json"
    );

    public static void Initialize()
    {
        string langToLoad = DefaultLanguage;

        try
        {
            if (File.Exists(SettingsFilePath))
            {
                var json = File.ReadAllText(SettingsFilePath);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("Language", out var langProp))
                {
                    var saved = langProp.GetString();
                    if (!string.IsNullOrEmpty(saved) && IsSupported(saved))
                    {
                        langToLoad = saved;
                    }
                }
            }
        }
        catch
        {
            langToLoad = DefaultLanguage;
        }

        ApplyLanguage(langToLoad, persist: false);
    }

    public static bool IsSupported(string code)
    {
        foreach (var lang in SupportedLanguages)
        {
            if (string.Equals(lang.Code, code, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public static void SetLanguage(string cultureCode)
    {
        if (!IsSupported(cultureCode))
        {
            cultureCode = DefaultLanguage;
        }

        if (string.Equals(CurrentLanguage, cultureCode, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        ApplyLanguage(cultureCode, persist: true);
    }

    private static void ApplyLanguage(string cultureCode, bool persist)
    {
        CurrentLanguage = cultureCode;

        var dictUri = new Uri($"Localization/Strings.{cultureCode}.xaml", UriKind.Relative);
        var newDict = new ResourceDictionary { Source = dictUri };

        var app = System.Windows.Application.Current;
        if (app != null)
        {
            var merged = app.Resources.MergedDictionaries;
            ResourceDictionary? existing = null;

            foreach (var dict in merged)
            {
                if (dict.Source != null && dict.Source.OriginalString.Contains("Localization/Strings."))
                {
                    existing = dict;
                    break;
                }
            }

            if (existing != null)
            {
                var index = merged.IndexOf(existing);
                merged[index] = newDict;
            }
            else
            {
                merged.Add(newDict);
            }
        }

        if (persist)
        {
            SaveSettings(cultureCode);
        }

        LanguageChanged?.Invoke();
    }

    private static void SaveSettings(string cultureCode)
    {
        try
        {
            var dir = Path.GetDirectoryName(SettingsFilePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var json = JsonSerializer.Serialize(new { Language = cultureCode }, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SettingsFilePath, json);
        }
        catch
        {
            // Ignore settings save errors gracefully
        }
    }

    public static string GetString(string key, params object?[] args)
    {
        try
        {
            var app = System.Windows.Application.Current;
            object? res = app?.TryFindResource(key);

            if (res is string s)
            {
                return args != null && args.Length > 0 ? string.Format(s, args) : s;
            }
        }
        catch
        {
            // Fallback to key
        }

        return key;
    }
}
