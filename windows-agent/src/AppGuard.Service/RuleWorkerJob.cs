using System.Text.Json.Serialization;

namespace AppGuard.Service;

internal sealed class RuleWorkerRequest
{
    [JsonPropertyName("job_id")] public string JobId { get; set; } = "";
    [JsonPropertyName("kind")] public string Kind { get; set; } = "";
    [JsonPropertyName("input_file_name")] public string InputFileName { get; set; } = "";
}

internal sealed class RuleWorkerResult
{
    [JsonPropertyName("success")] public bool Success { get; set; }
    [JsonPropertyName("rule_count")] public int RuleCount { get; set; }
    [JsonPropertyName("kind")] public string Kind { get; set; } = "";
    [JsonPropertyName("elapsed_seconds")] public double ElapsedSeconds { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
}
