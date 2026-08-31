using System.Text.Json.Serialization;

namespace AppGuard.Core;

public sealed class AgentConfig
{
    [JsonPropertyName("server_url")] public string ServerUrl { get; set; } = "";
    [JsonPropertyName("device_id")] public string DeviceId { get; set; } = "";
    [JsonPropertyName("device_key")] public string DeviceKey { get; set; } = "";
}

public sealed class AgentState
{
    [JsonPropertyName("learning_mode")] public bool LearningMode { get; set; }
    [JsonPropertyName("learning_started")] public string? LearningStarted { get; set; }
    [JsonPropertyName("base_policy_id")] public string? BasePolicyId { get; set; }
    [JsonPropertyName("last_record_id")] public long LastRecordId { get; set; }
    [JsonPropertyName("policy_version")] public int PolicyVersion { get; set; } = 1;
}

public sealed class HeartbeatRequest
{
    [JsonPropertyName("learning_mode")] public bool LearningMode { get; set; }
    [JsonPropertyName("policy_mode")] public string PolicyMode { get; set; } = "unknown";
    [JsonPropertyName("script_enforcement_disabled")] public bool? ScriptEnforcementDisabled { get; set; }
    [JsonPropertyName("agent_version")] public string AgentVersion { get; set; } = "1.0.0-rc.10";
    [JsonPropertyName("os_version")] public string? OsVersion { get; set; }
    [JsonPropertyName("update_status")] public string? UpdateStatus { get; set; }
    [JsonPropertyName("update_result")] public string? UpdateResult { get; set; }
    [JsonPropertyName("background_policy_status")] public string? BackgroundPolicyStatus { get; set; }
    [JsonPropertyName("background_policy_pending")] public int? BackgroundPolicyPending { get; set; }
    [JsonPropertyName("background_policy_failed")] public int? BackgroundPolicyFailed { get; set; }
    [JsonPropertyName("background_policy_error")] public string? BackgroundPolicyError { get; set; }
    [JsonPropertyName("background_policy_oldest_at")] public string? BackgroundPolicyOldestAt { get; set; }
    [JsonPropertyName("background_work")] public List<BackgroundWorkSummary> BackgroundWork { get; set; } = [];
    [JsonPropertyName("service_status")] public string ServiceStatus { get; set; } = "running";
    [JsonPropertyName("rule_worker_status")] public string? RuleWorkerStatus { get; set; }
    [JsonPropertyName("tray_status")] public string? TrayStatus { get; set; }
    [JsonPropertyName("last_policy_refresh_at")] public string? LastPolicyRefreshAt { get; set; }
    [JsonPropertyName("last_background_success_at")] public string? LastBackgroundSuccessAt { get; set; }
    [JsonPropertyName("last_event_upload_at")] public string? LastEventUploadAt { get; set; }
    [JsonPropertyName("last_command_poll_at")] public string? LastCommandPollAt { get; set; }
}

public sealed class EventUpload
{
    [JsonPropertyName("event_id")] public int EventId { get; set; }
    [JsonPropertyName("record_id")] public long? RecordId { get; set; }
    [JsonPropertyName("occurred_at")] public string? OccurredAt { get; set; }
    [JsonPropertyName("file_path")] public string? FilePath { get; set; }
    [JsonPropertyName("parent_path")] public string? ParentPath { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("publisher")] public string? Publisher { get; set; }
    [JsonPropertyName("product_name")] public string? ProductName { get; set; }
    [JsonPropertyName("file_version")] public string? FileVersion { get; set; }
    [JsonPropertyName("raw")] public Dictionary<string,string?> Raw { get; set; } = new();
}

public sealed class ApprovalRequest
{
    [JsonPropertyName("file_path")] public string FilePath { get; set; } = "";
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("publisher")] public string? Publisher { get; set; }
    [JsonPropertyName("product_name")] public string? ProductName { get; set; }
    [JsonPropertyName("file_version")] public string? FileVersion { get; set; }
    [JsonPropertyName("reason")] public string? Reason { get; set; }
    [JsonPropertyName("requested_by")] public string? RequestedBy { get; set; }
    [JsonPropertyName("policy_source_path")] public string? PolicySourcePath { get; set; }
}

public sealed class ApprovalComponent
{
    [JsonPropertyName("file_path")] public string FilePath { get; set; } = "";
    [JsonPropertyName("policy_source_path")] public string? PolicySourcePath { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("publisher")] public string? Publisher { get; set; }
    [JsonPropertyName("product_name")] public string? ProductName { get; set; }
    [JsonPropertyName("file_version")] public string? FileVersion { get; set; }
    [JsonPropertyName("parent_path")] public string? ParentPath { get; set; }
    [JsonPropertyName("record_id")] public long? RecordId { get; set; }
}

public sealed class ApprovalSessionRequest
{
    [JsonPropertyName("components")] public List<ApprovalComponent> Components { get; set; } = [];
    [JsonPropertyName("reason")] public string? Reason { get; set; }
    [JsonPropertyName("requested_by")] public string? RequestedBy { get; set; }
    [JsonPropertyName("session_key")] public string? SessionKey { get; set; }
}


public sealed class ApplicationDispositionRequest
{
    [JsonPropertyName("file_path")] public string FilePath { get; set; } = "";
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("publisher")] public string? Publisher { get; set; }
    [JsonPropertyName("product_name")] public string? ProductName { get; set; }
    [JsonPropertyName("file_version")] public string? FileVersion { get; set; }
    [JsonPropertyName("requested_by")] public string? RequestedBy { get; set; }
}

public sealed class ApplicationDispositionResponse
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("state")] public string State { get; set; } = "unknown";
    [JsonPropertyName("request_id")] public long? RequestId { get; set; }
    [JsonPropertyName("request_status")] public string? RequestStatus { get; set; }
    [JsonPropertyName("policy_id")] public string? PolicyId { get; set; }
    [JsonPropertyName("rule_type")] public string? RuleType { get; set; }
    [JsonPropertyName("decision_note")] public string? DecisionNote { get; set; }
}

public sealed class ApprovalResponse
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("already_approved")] public bool AlreadyApproved { get; set; }
    [JsonPropertyName("duplicate")] public bool Duplicate { get; set; }
    [JsonPropertyName("blocked")] public bool Blocked { get; set; }
    [JsonPropertyName("decision_note")] public string? DecisionNote { get; set; }
    [JsonPropertyName("request_id")] public long? RequestId { get; set; }
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("policy_id")] public string? PolicyId { get; set; }
    [JsonPropertyName("rule_type")] public string? RuleType { get; set; }
}

public sealed class ApprovalStatusInfo
{
    [JsonPropertyName("id")] public long Id { get; set; }
    [JsonPropertyName("file_path")] public string FilePath { get; set; } = "";
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("publisher")] public string? Publisher { get; set; }
    [JsonPropertyName("product_name")] public string? ProductName { get; set; }
    [JsonPropertyName("file_version")] public string? FileVersion { get; set; }
    [JsonPropertyName("reason")] public string? Reason { get; set; }
    [JsonPropertyName("requested_by")] public string? RequestedBy { get; set; }
    [JsonPropertyName("status")] public string Status { get; set; } = "unknown";
    [JsonPropertyName("created_at")] public string? CreatedAt { get; set; }
    [JsonPropertyName("decided_at")] public string? DecidedAt { get; set; }
    [JsonPropertyName("decided_by")] public string? DecidedBy { get; set; }
    [JsonPropertyName("decision_note")] public string? DecisionNote { get; set; }
    [JsonPropertyName("policy_id")] public string? PolicyId { get; set; }
    [JsonPropertyName("rule_type")] public string? RuleType { get; set; }
    [JsonPropertyName("component_count")] public int ComponentCount { get; set; } = 1;
    [JsonPropertyName("components")] public List<ApprovalComponent> Components { get; set; } = [];
}

public sealed class AgentCommand
{
    [JsonPropertyName("id")] public long Id { get; set; }
    [JsonPropertyName("command_type")] public string CommandType { get; set; } = "";
    [JsonPropertyName("payload")] public Dictionary<string,object?> Payload { get; set; } = new();
    [JsonPropertyName("created_at")] public string? CreatedAt { get; set; }
    [JsonPropertyName("claim_token")] public string? ClaimToken { get; set; }
}

public sealed class BackgroundPolicyReport
{
    [JsonPropertyName("request_id")] public long RequestId { get; set; }
    [JsonPropertyName("scoped_policy_id")] public long? ScopedPolicyId { get; set; }
    [JsonPropertyName("status")] public string Status { get; set; } = "";
    [JsonPropertyName("policy_id")] public string? PolicyId { get; set; }
    [JsonPropertyName("detail")] public string? Detail { get; set; }
    [JsonPropertyName("components")] public List<ApprovalComponent> Components { get; set; } = [];
}

public sealed class CommandComplete
{
    [JsonPropertyName("claim_token")] public string? ClaimToken { get; set; }
    [JsonPropertyName("success")] public bool Success { get; set; }
    [JsonPropertyName("result")] public string? Result { get; set; }
    [JsonPropertyName("policy_id")] public string? PolicyId { get; set; }
    [JsonPropertyName("rule_type")] public string? RuleType { get; set; }
    [JsonPropertyName("file_path")] public string? FilePath { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("publisher")] public string? Publisher { get; set; }
    [JsonPropertyName("product_name")] public string? ProductName { get; set; }
    [JsonPropertyName("file_version")] public string? FileVersion { get; set; }
    [JsonPropertyName("background_queued")] public bool BackgroundQueued { get; set; }
}

public sealed class SupplementalResult
{
    [JsonPropertyName("policy_id")] public string PolicyId { get; set; } = "";
    [JsonPropertyName("rule_type")] public string? RuleType { get; set; }
    [JsonPropertyName("file_path")] public string? FilePath { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("publisher")] public string? Publisher { get; set; }
    [JsonPropertyName("product_name")] public string? ProductName { get; set; }
    [JsonPropertyName("file_version")] public string? FileVersion { get; set; }
    [JsonPropertyName("requested_files")] public int RequestedFiles { get; set; }
    [JsonPropertyName("policy_files")] public int PolicyFiles { get; set; }
    [JsonPropertyName("expanded_files")] public int ExpandedFiles { get; set; }
    [JsonPropertyName("primary_rule_mode")] public string? PrimaryRuleMode { get; set; }
    [JsonPropertyName("background_queued")] public bool BackgroundQueued { get; set; }
}


public sealed class PolicyProgressInfo
{
    [JsonPropertyName("request_id")] public long RequestId { get; set; }
    [JsonPropertyName("phase")] public string Phase { get; set; } = "";
    [JsonPropertyName("message")] public string Message { get; set; } = "";
    [JsonPropertyName("file_count")] public int FileCount { get; set; }
    [JsonPropertyName("updated_at")] public string? UpdatedAt { get; set; }
}

public sealed class PipeRequest
{
    [JsonPropertyName("action")] public string Action { get; set; } = "";
    [JsonPropertyName("file_path")] public string? FilePath { get; set; }
    [JsonPropertyName("reason")] public string? Reason { get; set; }
    [JsonPropertyName("requested_by")] public string? RequestedBy { get; set; }
    [JsonPropertyName("record_id")] public long? RecordId { get; set; }
    [JsonPropertyName("parent_path")] public string? ParentPath { get; set; }
    [JsonPropertyName("component_record_ids")] public List<long> ComponentRecordIds { get; set; } = [];
    [JsonPropertyName("session_key")] public string? SessionKey { get; set; }
    [JsonPropertyName("installation_id")] public long? InstallationId { get; set; }
}

public sealed class BlockedSnapshot
{
    [JsonPropertyName("record_id")] public long RecordId { get; set; }
    [JsonPropertyName("original_path")] public string OriginalPath { get; set; } = "";
    [JsonPropertyName("parent_path")] public string? ParentPath { get; set; }
    [JsonPropertyName("cached_path")] public string? CachedPath { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("publisher")] public string? Publisher { get; set; }
    [JsonPropertyName("product_name")] public string? ProductName { get; set; }
    [JsonPropertyName("file_version")] public string? FileVersion { get; set; }
    [JsonPropertyName("captured_at")] public string? CapturedAt { get; set; }
}

public sealed class PipeResponse
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("message")] public string Message { get; set; } = "";
    [JsonPropertyName("request_id")] public long? RequestId { get; set; }
    [JsonPropertyName("request_status")] public string? RequestStatus { get; set; }
    [JsonPropertyName("already_approved")] public bool AlreadyApproved { get; set; }
    [JsonPropertyName("duplicate")] public bool Duplicate { get; set; }
    [JsonPropertyName("blocked")] public bool Blocked { get; set; }
    [JsonPropertyName("disposition")] public string? Disposition { get; set; }
    [JsonPropertyName("decision_note")] public string? DecisionNote { get; set; }
    [JsonPropertyName("mode")] public string? Mode { get; set; }
    [JsonPropertyName("requests")] public List<ApprovalStatusInfo> Requests { get; set; } = [];
    [JsonPropertyName("snapshot")] public BlockedSnapshot? Snapshot { get; set; }
    [JsonPropertyName("progress")] public PolicyProgressInfo? Progress { get; set; }
    [JsonPropertyName("installations")] public List<InstallationStatusInfo> Installations { get; set; } = [];
    [JsonPropertyName("installation_mode")] public InstallationModeState? InstallationMode { get; set; }
    [JsonPropertyName("installation_id")] public long? InstallationId { get; set; }
}
