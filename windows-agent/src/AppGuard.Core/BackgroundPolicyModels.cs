using System.Text.Json.Serialization;

namespace AppGuard.Core;

public static class BackgroundPolicyStatuses
{
    public const string Queued = "queued";
    public const string Processing = "processing";
    public const string Ready = "ready";
    public const string Installed = "installed";
    public const string Superseded = "superseded";
    public const string Expired = "expired";
    public const string Failed = "failed";
    public const string SkippedEphemeral = "skipped_ephemeral";
    public const string NeedsAttention = "needs_attention";
}

public static class BackgroundPolicyRecovery
{
    public static void PrepareSupersededRule(RuleCacheEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        entry.Status = BackgroundPolicyStatuses.Superseded;
        entry.Attempts = 0;
        entry.LastError = null;
    }
}

public sealed class BackgroundWorkSummary
{
    [JsonPropertyName("key_digest")] public string KeyDigest { get; set; } = "";
    [JsonPropertyName("display_name")] public string DisplayName { get; set; } = "";
    [JsonPropertyName("kind")] public string Kind { get; set; } = "";
    [JsonPropertyName("status")] public string Status { get; set; } = "queued";
    [JsonPropertyName("attempts")] public int Attempts { get; set; }
    [JsonPropertyName("age_seconds")] public int? AgeSeconds { get; set; }
    [JsonPropertyName("elapsed_seconds")] public int? ElapsedSeconds { get; set; }
    [JsonPropertyName("rule_mode")] public string? RuleMode { get; set; }
    [JsonPropertyName("error_category")] public string? ErrorCategory { get; set; }
    [JsonPropertyName("updated_at")] public string UpdatedAt { get; set; } = "";
}

public sealed class RuleCacheEntry
{
    [JsonPropertyName("cache_key")] public string CacheKey { get; set; } = "";
    [JsonPropertyName("kind")] public string Kind { get; set; } = "product"; // product|<signer>|<ProductName> or hash|<SHA256>
    [JsonPropertyName("status")] public string Status { get; set; } = BackgroundPolicyStatuses.Queued;
    [JsonPropertyName("publisher")] public string? Publisher { get; set; }
    [JsonPropertyName("product_name")] public string? ProductName { get; set; }
    [JsonPropertyName("minimum_file_version")] public string? MinimumFileVersion { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("representative_path")] public string RepresentativePath { get; set; } = "";
    [JsonPropertyName("fragment_xml_path")] public string? FragmentXmlPath { get; set; }
    [JsonPropertyName("attempts")] public int Attempts { get; set; }
    [JsonPropertyName("last_error")] public string? LastError { get; set; }
    [JsonPropertyName("owners")] public List<string> Owners { get; set; } = [];
    [JsonPropertyName("updated_at")] public string UpdatedAt { get; set; } = DateTimeOffset.UtcNow.ToString("O");
}

public sealed class BackgroundBundleMember
{
    [JsonPropertyName("file_path")] public string FilePath { get; set; } = "";
    [JsonPropertyName("publisher")] public string? Publisher { get; set; }
    [JsonPropertyName("product_name")] public string? ProductName { get; set; }
    [JsonPropertyName("file_version")] public string? FileVersion { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("rule_key")] public string RuleKey { get; set; } = "";
}

public sealed class BackgroundBundleJob
{
    [JsonPropertyName("request_id")] public long RequestId { get; set; }
    [JsonPropertyName("scoped_policy_id")] public long? ScopedPolicyId { get; set; }
    [JsonPropertyName("application_root")] public string ApplicationRoot { get; set; } = "";
    [JsonPropertyName("status")] public string Status { get; set; } = BackgroundPolicyStatuses.Queued;
    [JsonPropertyName("required_rule_keys")] public List<string> RequiredRuleKeys { get; set; } = [];
    [JsonPropertyName("members")] public List<BackgroundBundleMember> Members { get; set; } = [];
    [JsonPropertyName("policy_id")] public string? PolicyId { get; set; }
    [JsonPropertyName("attempts")] public int Attempts { get; set; }
    [JsonPropertyName("last_error")] public string? LastError { get; set; }
    [JsonPropertyName("updated_at")] public string UpdatedAt { get; set; } = DateTimeOffset.UtcNow.ToString("O");
}

public sealed class LearningRuleReference
{
    [JsonPropertyName("record_id")] public long? RecordId { get; set; }
    [JsonPropertyName("file_path")] public string FilePath { get; set; } = "";
    [JsonPropertyName("rule_key")] public string RuleKey { get; set; } = "";
}

public sealed class BackgroundPolicySnapshot
{
    [JsonPropertyName("rules")] public List<RuleCacheEntry> Rules { get; set; } = [];
    [JsonPropertyName("bundles")] public List<BackgroundBundleJob> Bundles { get; set; } = [];
    [JsonPropertyName("learning")] public List<LearningRuleReference> Learning { get; set; } = [];
}

public sealed class BackgroundPolicyQueueStatus
{
    public int Pending { get; init; }
    public int Failed { get; init; }
    public string Status { get; init; } = "idle";
    public string? OldestPendingAt { get; init; }
    public string? LastError { get; init; }
}

public sealed class BackgroundPolicyRetryResult
{
    public int RulesReset { get; init; }
    public int BundlesReset { get; init; }
    public int TotalReset => RulesReset + BundlesReset;
}

public sealed class LearningPreparationStats
{
    public int Observed { get; set; }
    public int ProductCandidates { get; set; }
    public int HashCandidates { get; set; }
    public int Reused { get; set; }
    public int Queued { get; set; }
    public int Unpreparable { get; set; }
    public int IgnoredEphemeral { get; set; }
    public Dictionary<string, string> PreparedRuleKeysByPath { get; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class BackgroundRuleFragmentResult
{
    [JsonPropertyName("fragment_xml_path")] public string FragmentXmlPath { get; set; } = "";
    [JsonPropertyName("rule_count")] public int RuleCount { get; set; }
    [JsonPropertyName("kind")] public string Kind { get; set; } = "";
    [JsonPropertyName("elapsed_seconds")] public double ElapsedSeconds { get; set; }
}
