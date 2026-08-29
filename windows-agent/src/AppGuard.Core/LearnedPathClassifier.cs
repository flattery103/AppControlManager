namespace AppGuard.Core;

public static class LearnedPathClassifier
{
    public static bool IsExpectedDotNetExtraction(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.IndexOf('\0') >= 0) return false;

        var normalized = path.Trim().Replace('/', '\\');
        if (normalized.StartsWith(@"\\?\", StringComparison.Ordinal))
            normalized = normalized[4..];
        if (normalized.StartsWith(@"\\", StringComparison.Ordinal)) return false;

        var segments = normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0 || segments.Any(x => x is "." or "..")) return false;
        if (segments[0].Length != 2 || !char.IsLetter(segments[0][0]) || segments[0][1] != ':') return false;

        var userTemp = segments.Length >= 10 &&
            EqualsSegment(segments[1], "Users") &&
            !string.IsNullOrWhiteSpace(segments[2]) &&
            EqualsSegment(segments[3], "AppData") &&
            EqualsSegment(segments[4], "Local") &&
            EqualsSegment(segments[5], "Temp") &&
            EqualsSegment(segments[6], ".net") &&
            HasExtractionTail(segments, 7);

        var windowsTemp = segments.Length >= 7 &&
            EqualsSegment(segments[1], "Windows") &&
            EqualsSegment(segments[2], "Temp") &&
            EqualsSegment(segments[3], ".net") &&
            HasExtractionTail(segments, 4);

        return userTemp || windowsTemp;
    }

    private static bool HasExtractionTail(string[] segments, int applicationIndex)
        => segments.Length > applicationIndex + 2 &&
           !string.IsNullOrWhiteSpace(segments[applicationIndex]) &&
           !string.IsNullOrWhiteSpace(segments[applicationIndex + 1]) &&
           segments.Skip(applicationIndex + 2).All(x => !string.IsNullOrWhiteSpace(x));

    private static bool EqualsSegment(string value, string expected)
        => string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);
}
