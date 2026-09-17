using System;
using System.IO;

namespace OmniEye.Core.Configuration;

public class OmniEyeConfig
{
    public bool DeveloperMode { get; set; } = false;
    public string DbDirectory { get; set; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OmniEye");
    public string DbFileName { get; set; } = "config.db";
    public string KeyFileName { get; set; } = "master.key";
    public string PipeName { get; set; } = "OmniEyePipe";
    public int SelfHealingIntervalMs { get; set; } = 3000;
    public int PromptTimeoutSeconds { get; set; } = 60;

    public string DbFilePath => Path.Combine(DbDirectory, DbFileName);
    public string KeyFilePath => Path.Combine(DbDirectory, KeyFileName);
}
