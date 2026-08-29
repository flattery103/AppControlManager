using System.Text.Json.Serialization;

namespace AppGuard.Service;

internal static class RuleWorkerOperations
{
    private static readonly IReadOnlyDictionary<string, string> OutputFiles =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["product"] = "fragment.xml",
            ["hash"] = "fragment.xml",
            ["primary_allow"] = "policy.xml",
            ["deny_policy"] = "policy.xml"
        };

    public static bool TryGetOutputFile(string? operation, out string outputFileName)
    {
        outputFileName = "";
        return !string.IsNullOrWhiteSpace(operation) && OutputFiles.TryGetValue(operation, out outputFileName!);
    }

    public static bool IsFragmentOperation(string operation)
        => operation.Equals("product", StringComparison.OrdinalIgnoreCase) ||
           operation.Equals("hash", StringComparison.OrdinalIgnoreCase);
}

internal sealed class RuleWorkerRequest
{
    [JsonPropertyName("job_id")] public string JobId { get; set; } = "";
    [JsonPropertyName("operation")] public string Operation { get; set; } = "";
    [JsonPropertyName("input_file_name")] public string InputFileName { get; set; } = "";
}

public sealed class RuleWorkerResult
{
    [JsonPropertyName("success")] public bool Success { get; set; }
    [JsonPropertyName("operation")] public string Operation { get; set; } = "";
    [JsonPropertyName("rule_count")] public int RuleCount { get; set; }
    [JsonPropertyName("rule_mode")] public string RuleMode { get; set; } = "";
    [JsonPropertyName("elapsed_seconds")] public double ElapsedSeconds { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("file_path")] public string? FilePath { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("publisher")] public string? Publisher { get; set; }
    [JsonPropertyName("product_name")] public string? ProductName { get; set; }
    [JsonPropertyName("file_version")] public string? FileVersion { get; set; }
}
