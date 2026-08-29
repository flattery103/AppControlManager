using System.Text.Json.Serialization;

namespace AppGuard.Core;

public sealed class InstallationModeState
{
    [JsonPropertyName("active")] public bool Active { get; set; }
    [JsonPropertyName("installation_id")] public long InstallationId { get; set; }
    [JsonPropertyName("duration_minutes")] public int DurationMinutes { get; set; }
    [JsonPropertyName("trigger")] public string Trigger { get; set; } = "";
    [JsonPropertyName("actor")] public string Actor { get; set; } = "";
    [JsonPropertyName("started_at")] public string? StartedAt { get; set; }
    [JsonPropertyName("ends_at")] public string? EndsAt { get; set; }
    [JsonPropertyName("pending_report_status")] public string? PendingReportStatus { get; set; }
    [JsonPropertyName("pending_report_detail")] public string? PendingReportDetail { get; set; }
    [JsonPropertyName("pending_report_started_at")] public string? PendingReportStartedAt { get; set; }
    [JsonPropertyName("pending_report_ends_at")] public string? PendingReportEndsAt { get; set; }
    [JsonPropertyName("pending_report_completed_at")] public string? PendingReportCompletedAt { get; set; }
}

public sealed class InstallationStatusInfo
{
    [JsonPropertyName("id")] public long Id { get; set; }
    [JsonPropertyName("device_id")] public string DeviceId { get; set; } = "";
    [JsonPropertyName("file_path")] public string FilePath { get; set; } = "";
    [JsonPropertyName("product_name")] public string? ProductName { get; set; }
    [JsonPropertyName("requested_by")] public string? RequestedBy { get; set; }
    [JsonPropertyName("source")] public string Source { get; set; } = "user";
    [JsonPropertyName("status")] public string Status { get; set; } = "unknown";
    [JsonPropertyName("duration_minutes")] public int? DurationMinutes { get; set; }
    [JsonPropertyName("activation_expires_at")] public string? ActivationExpiresAt { get; set; }
    [JsonPropertyName("started_at")] public string? StartedAt { get; set; }
    [JsonPropertyName("ends_at")] public string? EndsAt { get; set; }
    [JsonPropertyName("decision_note")] public string? DecisionNote { get; set; }
}

public sealed class InstallationRequestResponse
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("duplicate")] public bool Duplicate { get; set; }
    [JsonPropertyName("installation_id")] public long InstallationId { get; set; }
    [JsonPropertyName("status")] public string Status { get; set; } = "unknown";
}

public sealed class InstallationStartRequest
{
    [JsonPropertyName("requested_by")] public string? RequestedBy { get; set; }
}

public sealed class InstallationReportRequest
{
    [JsonPropertyName("status")] public string Status { get; set; } = "";
    [JsonPropertyName("started_at")] public string? StartedAt { get; set; }
    [JsonPropertyName("ends_at")] public string? EndsAt { get; set; }
    [JsonPropertyName("completed_at")] public string? CompletedAt { get; set; }
    [JsonPropertyName("detail")] public string? Detail { get; set; }
}

public sealed class InstallationFinalizationResult
{
    public int LearnedCount { get; init; }
    public int InstalledRuleCount { get; init; }
    public int SkippedCount { get; init; }
    public bool HasWarnings => SkippedCount > 0;
}
