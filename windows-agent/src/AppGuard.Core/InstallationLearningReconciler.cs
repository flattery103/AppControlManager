namespace AppGuard.Core;

public sealed record InstallationLearnedFile(string? FilePath, long? RecordId);

public sealed class InstallationLearningPlan
{
    public IReadOnlyList<string> RequiredRuleKeys { get; init; } = [];
    public int SkippedCount { get; init; }
    public int IgnoredEphemeralCount { get; init; }
}

public static class InstallationLearningReconciler
{
    public static InstallationLearningPlan Create(
        IEnumerable<InstallationLearnedFile> learnedFiles,
        IReadOnlyDictionary<string, string> preparedRuleKeysByPath,
        IEnumerable<LearningRuleReference> existingReferences,
        ISet<string> readyRuleKeys,
        Func<string, bool> isAvailable,
        Func<string, bool>? isExpectedEphemeral = null)
    {
        var references = existingReferences
            .Where(x => x.RecordId.HasValue && !string.IsNullOrWhiteSpace(x.FilePath) && !string.IsNullOrWhiteSpace(x.RuleKey))
            .ToArray();
        var learned = learnedFiles.ToArray();
        var required = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var skipped = learned.Count(x => string.IsNullOrWhiteSpace(x.FilePath));
        var ignoredEphemeral = 0;

        foreach (var group in learned
                     .Where(x => !string.IsNullOrWhiteSpace(x.FilePath))
                     .GroupBy(x => x.FilePath!.Trim(), StringComparer.OrdinalIgnoreCase))
        {
            var path = group.Key;
            if (isExpectedEphemeral?.Invoke(path) == true)
            {
                ignoredEphemeral++;
                continue;
            }

            if (preparedRuleKeysByPath.TryGetValue(path, out var preparedKey) &&
                !string.IsNullOrWhiteSpace(preparedKey) &&
                (isAvailable(path) || readyRuleKeys.Contains(preparedKey)))
            {
                required.Add(preparedKey);
                continue;
            }
            var currentRecordIds = group.Where(x => x.RecordId.HasValue).Select(x => x.RecordId!.Value).ToHashSet();
            var existingKey = references
                .Where(x => string.Equals(x.FilePath.Trim(), path, StringComparison.OrdinalIgnoreCase) &&
                            x.RecordId.HasValue && currentRecordIds.Contains(x.RecordId.Value) &&
                            readyRuleKeys.Contains(x.RuleKey))
                .Select(x => x.RuleKey)
                .LastOrDefault();
            if (!string.IsNullOrWhiteSpace(existingKey))
            {
                required.Add(existingKey);
                continue;
            }
            skipped++;
        }

        return new InstallationLearningPlan
        {
            RequiredRuleKeys = required.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
            SkippedCount = skipped,
            IgnoredEphemeralCount = ignoredEphemeral
        };
    }

    public static string PreferAvailableRepresentative(string currentPath, string candidatePath, Func<string, bool> exists)
    {
        if (!string.IsNullOrWhiteSpace(currentPath) && exists(currentPath)) return currentPath;
        if (!string.IsNullOrWhiteSpace(candidatePath) && exists(candidatePath)) return candidatePath;
        return currentPath;
    }
}
