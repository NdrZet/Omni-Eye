using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace OmniEye.Core.Models;

public class CloudTunnelConfig
{
    public bool IsEnabled { get; set; } = false;
    public string Host { get; set; } = "127.0.0.1";
    public int MtprotoPort { get; set; } = 1443;
    public int Socks5Port { get; set; } = 10808;
    public bool EnableSocks5 { get; set; } = true;
    public string Secret { get; set; } = GenerateSecret();
    
    // Cloudflare Worker endpoints (e.g. "my-worker.username.workers.dev")
    public List<string> WorkerDomains { get; set; } = new();

    // DC redirection table for Telegram (defaults from Flowseal tg-ws-proxy)
    public Dictionary<int, string> DcRedirects { get; set; } = new()
    {
        { 1, "149.154.175.50" },
        { 2, "149.154.167.220" },
        { 3, "149.154.175.100" },
        { 4, "149.154.167.220" },
        { 5, "149.154.171.5" },
        { 203, "149.154.167.220" }
    };

    // System Proxy
    public bool EnableSystemProxy { get; set; } = false;
    public bool BypassRussianTraffic { get; set; } = true;

    // Fast generation of a random 16-byte hex secret
    public static string GenerateSecret()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexStringLower(bytes);
    }

    public string GetTelegramLink(string? customHost = null)
    {
        var h = string.IsNullOrWhiteSpace(customHost) ? Host : customHost;
        return $"tg://proxy?server={h}&port={MtprotoPort}&secret={Secret}";
    }

    public string GetWebTelegramLink(string? customHost = null)
    {
        var h = string.IsNullOrWhiteSpace(customHost) ? Host : customHost;
        return $"https://t.me/proxy?server={h}&port={MtprotoPort}&secret={Secret}";
    }

    public static string GetConfigFilePath()
    {
        return System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "OmniEye",
            "tunnel_config.json"
        );
    }

    public static CloudTunnelConfig Load()
    {
        try
        {
            var path = GetConfigFilePath();
            if (System.IO.File.Exists(path))
            {
                var json = System.IO.File.ReadAllText(path);
                var cfg = System.Text.Json.JsonSerializer.Deserialize<CloudTunnelConfig>(json);
                if (cfg != null)
                {
                    if (string.IsNullOrWhiteSpace(cfg.Secret))
                        cfg.Secret = GenerateSecret();
                    return cfg;
                }
            }
        }
        catch { }

        return new CloudTunnelConfig();
    }

    public void Save()
    {
        try
        {
            var path = GetConfigFilePath();
            var dir = System.IO.Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
            {
                System.IO.Directory.CreateDirectory(dir);
            }
            var json = System.Text.Json.JsonSerializer.Serialize(this, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            System.IO.File.WriteAllText(path, json);
        }
        catch { }
    }
}
