using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using OmniEye.Core.Configuration;
using OmniEye.Core.Models;
using OmniEye.Core.Security;
using OmniEye.Core.Storage;

namespace OmniEyeSvc.Network;

/// <summary>
/// Network Enforcer manages Windows Defender Firewall through the COM INetFwPolicy2 API.
/// Implements Zero-Trust: Block all outbound traffic by default, whitelisting only system essentials
/// (DNS, DHCP, Windows Update) and approved applications.
/// </summary>
public class FirewallEnforcer : IDisposable
{
    private readonly OmniEyeConfig _config;
    private readonly DatabaseManager _dbManager;
    private readonly ILogger<FirewallEnforcer> _logger;

    private CancellationTokenSource? _selfHealingCts;
    private Task? _selfHealingTask;
    private bool _isEnforced;

    // NET_FW_PROFILE_TYPE2 constants
    public const int NET_FW_PROFILE2_DOMAIN = 1;
    public const int NET_FW_PROFILE2_PRIVATE = 2;
    public const int NET_FW_PROFILE2_PUBLIC = 4;
    public const int NET_FW_PROFILE2_ALL = 0x7FFFFFFF;

    // NET_FW_ACTION constants
    public const int NET_FW_ACTION_BLOCK = 0;
    public const int NET_FW_ACTION_ALLOW = 1;

    // NET_FW_RULE_DIR constants
    public const int NET_FW_RULE_DIR_IN = 1;
    public const int NET_FW_RULE_DIR_OUT = 2;

    // NET_FW_IP_PROTOCOL constants
    public const int NET_FW_IP_PROTOCOL_TCP = 6;
    public const int NET_FW_IP_PROTOCOL_UDP = 17;
    public const int NET_FW_IP_PROTOCOL_ANY = 256;

    public const string RulePrefix = "OmniEye-";
    public const string DnsRuleName = "OmniEye-System-DNS";
    public const string DhcpRuleName = "OmniEye-System-DHCP";
    public const string WinUpdateRuleName = "OmniEye-System-WindowsUpdate";

    public bool IsEnforced => _isEnforced;

    public FirewallEnforcer(OmniEyeConfig config, DatabaseManager dbManager, ILogger<FirewallEnforcer> logger)
    {
        _config = config;
        _dbManager = dbManager;
        _logger = logger;
    }

    private dynamic GetPolicy()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
            ?? throw new InvalidOperationException("Could not load HNetCfg.FwPolicy2 COM component.");
        return Activator.CreateInstance(type)!;
    }

    private dynamic CreateRule()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FWRule")
            ?? throw new InvalidOperationException("Could not load HNetCfg.FWRule COM component.");
        return Activator.CreateInstance(type)!;
    }

    /// <summary>
    /// Applies zero-trust policy: blocks default outbound and sets system rules & whitelisted app rules.
    /// </summary>
    public void ApplyPolicy()
    {
        try
        {
            _logger.LogInformation("Applying OmniEye Zero-Trust Firewall Policy...");
            dynamic policy = GetPolicy();

            // 1. Remove previous OmniEye rules to ensure a clean state
            RemoveOmniEyeRules(policy);

            // 2. Add System Rules (DNS, DHCP, Windows Update)
            AddSystemRules(policy);

            // 3. Add Whitelist Rules
            var whitelist = _dbManager.GetWhitelist();
            ApplyWhitelistRules(policy, whitelist);

            // 4. Set Default Outbound Action = Block
            SetDefaultOutboundAction(policy, NET_FW_ACTION_BLOCK);

            _isEnforced = true;
            _logger.LogInformation("Zero-Trust Firewall Policy successfully applied. Outbound default = BLOCK.");

            // 5. Start Self-Healing Loop if not in DeveloperMode
            if (!_config.DeveloperMode)
            {
                StartSelfHealing();
            }
            else
            {
                _logger.LogInformation("DeveloperMode is active: Self-Healing watchdog is disabled.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply Zero-Trust Firewall Policy: {Message}", ex.Message);
            if (!_config.DeveloperMode)
            {
                throw;
            }
        }
    }

    /// <summary>
    /// Restores default outbound policy to Allow and cleans up OmniEye rules.
    /// </summary>
    public void RollbackPolicy()
    {
        try
        {
            StopSelfHealing();

            _logger.LogInformation("Rolling back OmniEye Firewall Policy (Restoring Outbound = ALLOW)...");
            dynamic policy = GetPolicy();

            // 1. Restore Default Outbound Action to Allow
            SetDefaultOutboundAction(policy, NET_FW_ACTION_ALLOW);

            // 2. Remove all OmniEye rules
            RemoveOmniEyeRules(policy);

            _isEnforced = false;
            _logger.LogInformation("Firewall policy successfully reverted to standard default.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error while rolling back firewall policy: {Message}", ex.Message);
        }
    }

    public void AddApplicationRule(WhitelistEntry entry)
    {
        try
        {
            dynamic policy = GetPolicy();
            var ruleName = $"{RulePrefix}App-{entry.Id}";

            // Check signature if not in developer mode
            if (!_config.DeveloperMode)
            {
                var sig = AuthenticodeVerifier.VerifyFile(entry.FilePath);
                if (!sig.IsValid)
                {
                    _logger.LogWarning("Rejecting firewall rule for {Path}: signature invalid ({Msg})", entry.FilePath, sig.StatusMessage);
                    return;
                }
            }

            dynamic rule = CreateRule();
            rule.Name = ruleName;
            rule.Description = $"OmniEye Whitelist Rule for {entry.FileName}";
            rule.ApplicationName = entry.FilePath;
            rule.Action = NET_FW_ACTION_ALLOW;
            rule.Direction = NET_FW_RULE_DIR_OUT;
            rule.Enabled = entry.IsEnabled;
            rule.Profiles = NET_FW_PROFILE2_ALL;

            policy.Rules.Add(rule);
            _logger.LogInformation("Added outbound firewall rule for: {Path}", entry.FilePath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to add application rule for {Path}: {Message}", entry.FilePath, ex.Message);
        }
    }

    public void RemoveApplicationRule(int entryId)
    {
        try
        {
            dynamic policy = GetPolicy();
            var ruleName = $"{RulePrefix}App-{entryId}";
            try
            {
                policy.Rules.Remove(ruleName);
                _logger.LogInformation("Removed firewall rule {RuleName}", ruleName);
            }
            catch
            {
                // Rule did not exist
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove application rule {Id}: {Message}", entryId, ex.Message);
        }
    }

    private void SetDefaultOutboundAction(dynamic policy, int action)
    {
        int[] profiles = { NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC };
        foreach (var profile in profiles)
        {
            try
            {
                policy.DefaultOutboundAction[profile] = action;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Could not set DefaultOutboundAction on profile {Profile}: {Message}", profile, ex.Message);
            }
        }
    }

    private void AddSystemRules(dynamic policy)
    {
        // 1. DNS: UDP Port 53 Outbound
        dynamic dnsRuleUdp = CreateRule();
        dnsRuleUdp.Name = $"{DnsRuleName}-UDP";
        dnsRuleUdp.Description = "OmniEye System Rule: Allow Outbound DNS (UDP 53)";
        dnsRuleUdp.Protocol = NET_FW_IP_PROTOCOL_UDP;
        dnsRuleUdp.RemotePorts = "53";
        dnsRuleUdp.Action = NET_FW_ACTION_ALLOW;
        dnsRuleUdp.Direction = NET_FW_RULE_DIR_OUT;
        dnsRuleUdp.Enabled = true;
        dnsRuleUdp.Profiles = NET_FW_PROFILE2_ALL;
        policy.Rules.Add(dnsRuleUdp);

        // 1b. DNS: TCP Port 53 Outbound
        dynamic dnsRuleTcp = CreateRule();
        dnsRuleTcp.Name = $"{DnsRuleName}-TCP";
        dnsRuleTcp.Description = "OmniEye System Rule: Allow Outbound DNS (TCP 53)";
        dnsRuleTcp.Protocol = NET_FW_IP_PROTOCOL_TCP;
        dnsRuleTcp.RemotePorts = "53";
        dnsRuleTcp.Action = NET_FW_ACTION_ALLOW;
        dnsRuleTcp.Direction = NET_FW_RULE_DIR_OUT;
        dnsRuleTcp.Enabled = true;
        dnsRuleTcp.Profiles = NET_FW_PROFILE2_ALL;
        policy.Rules.Add(dnsRuleTcp);

        // 2. DHCP: UDP Ports 67, 68 Outbound
        dynamic dhcpRule = CreateRule();
        dhcpRule.Name = DhcpRuleName;
        dhcpRule.Description = "OmniEye System Rule: Allow Outbound DHCP (UDP 67, 68)";
        dhcpRule.Protocol = NET_FW_IP_PROTOCOL_UDP;
        dhcpRule.RemotePorts = "67,68";
        dhcpRule.Action = NET_FW_ACTION_ALLOW;
        dhcpRule.Direction = NET_FW_RULE_DIR_OUT;
        dhcpRule.Enabled = true;
        dhcpRule.Profiles = NET_FW_PROFILE2_ALL;
        policy.Rules.Add(dhcpRule);

        // 3. Windows Update Service Rule
        dynamic winUpdateRule = CreateRule();
        winUpdateRule.Name = WinUpdateRuleName;
        winUpdateRule.Description = "OmniEye System Rule: Allow Outbound Windows Update (wuauserv)";
        winUpdateRule.ServiceName = "wuauserv";
        winUpdateRule.Action = NET_FW_ACTION_ALLOW;
        winUpdateRule.Direction = NET_FW_RULE_DIR_OUT;
        winUpdateRule.Enabled = true;
        winUpdateRule.Profiles = NET_FW_PROFILE2_ALL;
        try
        {
            policy.Rules.Add(winUpdateRule);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Could not bind Windows Update service rule: {Message}", ex.Message);
        }
    }

    private void ApplyWhitelistRules(dynamic policy, IEnumerable<WhitelistEntry> entries)
    {
        foreach (var entry in entries)
        {
            if (!entry.IsEnabled || !File.Exists(entry.FilePath))
                continue;

            // In production, enforce valid signature
            if (!_config.DeveloperMode)
            {
                var sig = AuthenticodeVerifier.VerifyFile(entry.FilePath);
                if (!sig.IsValid)
                {
                    _logger.LogWarning("Skipping unverified file in production: {Path}", entry.FilePath);
                    continue;
                }
            }

            dynamic rule = CreateRule();
            rule.Name = $"{RulePrefix}App-{entry.Id}";
            rule.Description = $"OmniEye Whitelist Rule for {entry.FileName}";
            rule.ApplicationName = entry.FilePath;
            rule.Action = NET_FW_ACTION_ALLOW;
            rule.Direction = NET_FW_RULE_DIR_OUT;
            rule.Enabled = true;
            rule.Profiles = NET_FW_PROFILE2_ALL;

            policy.Rules.Add(rule);
        }
    }

    private void RemoveOmniEyeRules(dynamic policy)
    {
        try
        {
            var rulesToDelete = new List<string>();
            foreach (var rule in policy.Rules)
            {
                try
                {
                    string name = rule.Name;
                    if (name != null && name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        rulesToDelete.Add(name);
                    }
                }
                catch { }
            }

            foreach (var name in rulesToDelete)
            {
                try
                {
                    policy.Rules.Remove(name);
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Error enumerating rules to remove: {Message}", ex.Message);
        }
    }

    private void StartSelfHealing()
    {
        StopSelfHealing();
        _selfHealingCts = new CancellationTokenSource();
        var token = _selfHealingCts.Token;

        _selfHealingTask = Task.Run(async () =>
        {
            _logger.LogInformation("Self-Healing watchdog started. Interval: {Interval} ms", _config.SelfHealingIntervalMs);
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_config.SelfHealingIntervalMs, token);
                    VerifyAndHeal();
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Self-Healing check encountered an error: {Message}", ex.Message);
                }
            }
        }, token);
    }

    private void StopSelfHealing()
    {
        if (_selfHealingCts != null)
        {
            _selfHealingCts.Cancel();
            _selfHealingCts.Dispose();
            _selfHealingCts = null;
            _selfHealingTask = null;
        }
    }

    private void VerifyAndHeal()
    {
        try
        {
            dynamic policy = GetPolicy();

            // Check if Default Outbound is still Block
            int[] profiles = { NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC };
            bool tampered = false;

            foreach (var profile in profiles)
            {
                int action = policy.DefaultOutboundAction[profile];
                if (action != NET_FW_ACTION_BLOCK)
                {
                    _logger.LogWarning("TAMPER DETECTED: Profile {Profile} Outbound Action changed to {Action}! Re-blocking immediately.", profile, action);
                    policy.DefaultOutboundAction[profile] = NET_FW_ACTION_BLOCK;
                    tampered = true;
                }
            }

            if (tampered)
            {
                // Re-verify system and whitelist rules
                _logger.LogInformation("Re-enforcing OmniEye rules following detected tampering...");
                AddSystemRules(policy);
                var whitelist = _dbManager.GetWhitelist();
                ApplyWhitelistRules(policy, whitelist);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during firewall integrity check: {Message}", ex.Message);
        }
    }

    public void Dispose()
    {
        StopSelfHealing();
    }
}
