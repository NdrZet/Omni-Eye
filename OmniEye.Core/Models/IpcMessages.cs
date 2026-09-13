using System;
using System.Collections.Generic;

namespace OmniEye.Core.Models;

/// <summary>
/// Envelope for JSON-based IPC messages between OmniEyeSvc and OmniEyeTray.
/// </summary>
public class IpcMessage
{
    public string Type { get; set; } = string.Empty;
    public string? CorrelationId { get; set; }
    public string? PayloadJson { get; set; }

    public static IpcMessage Create<T>(string type, T payload, string? correlationId = null)
    {
        return new IpcMessage
        {
            Type = type,
            CorrelationId = correlationId,
            PayloadJson = Newtonsoft.Json.JsonConvert.SerializeObject(payload)
        };
    }

    public T? GetPayload<T>()
    {
        if (string.IsNullOrEmpty(PayloadJson))
            return default;
        return Newtonsoft.Json.JsonConvert.DeserializeObject<T>(PayloadJson);
    }
}

public static class IpcMessageTypes
{
    public const string GetStatusRequest = "status.request";
    public const string GetStatusResponse = "status.response";

    public const string GetWhitelistRequest = "whitelist.get.request";
    public const string GetWhitelistResponse = "whitelist.get.response";

    public const string AddWhitelistRequest = "whitelist.add.request";
    public const string AddWhitelistResponse = "whitelist.add.response";

    public const string RemoveWhitelistRequest = "whitelist.remove.request";
    public const string RemoveWhitelistResponse = "whitelist.remove.response";

    public const string InjectionPromptNotification = "injection.prompt.notification";
    public const string InjectionPromptAction = "injection.prompt.action";

    public const string SetFirewallPolicyRequest = "firewall.set_policy.request";
    public const string SetFirewallPolicyResponse = "firewall.set_policy.response";
}

public class SetFirewallPolicyRequest
{
    public bool BlockOutbound { get; set; }
}

public class SetFirewallPolicyResponse
{
    public bool Success { get; set; }
    public bool OutboundBlocked { get; set; }
    public string Message { get; set; } = string.Empty;
}

public class StatusResponse
{
    public bool IsRunning { get; set; }
    public bool DeveloperMode { get; set; }
    public bool OutboundBlocked { get; set; }
    public int WhitelistCount { get; set; }
    public int BlockedAttemptsCount { get; set; }
    public TimeSpan Uptime { get; set; }
    public DateTime ServerTime { get; set; } = DateTime.UtcNow;
}

public class WhitelistResponse
{
    public List<WhitelistEntry> Entries { get; set; } = new();
}

public class AddWhitelistRequest
{
    public string FilePath { get; set; } = string.Empty;
    public bool BypassSignatureCheck { get; set; }
}

public class AddWhitelistResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public WhitelistEntry? Entry { get; set; }
}

public class RemoveWhitelistRequest
{
    public int Id { get; set; }
    public string? FilePath { get; set; }
}

public class RemoveWhitelistResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
}

public class InjectionPromptNotification
{
    public string PromptId { get; set; } = Guid.NewGuid().ToString();
    public int SourcePid { get; set; }
    public string SourcePath { get; set; } = string.Empty;
    public int TargetPid { get; set; }
    public string TargetPath { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public int TimeoutSeconds { get; set; } = 60;
}

public class InjectionPromptAction
{
    public string PromptId { get; set; } = string.Empty;
    /// <summary>
    /// "kill" or "ignore"
    /// </summary>
    public string Action { get; set; } = "kill";
}
