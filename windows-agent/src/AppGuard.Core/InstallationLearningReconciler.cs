namespace AppGuard.Core;

public sealed class InstallationLearningPlan
{
    public IReadOnlyList<string> RequiredRuleKeys { get; init; } = [];
    public int SkippedCount { get; init; }
}

public static class InstallationLearningReconciler
{
    public static InstallationLearningPlan Create(
        IEnumerable<string?> learnedPaths,
        IReadOnlyDictionary<string, string> preparedRuleKeysByPath,
        IEnumerable<LearningRuleReference> existingReferences,
        ISet<string> readyRuleKeys,
        Func<string, bool> isAvailable)
    {
        var references = existingReferences
            .Where(x => !string.IsNullOrWhiteSpace(x.FilePath) && !string.IsNullOrWhiteSpace(x.RuleKey))
            .GroupBy(x => x.FilePath.Trim(), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.Last().RuleKey, StringComparer.OrdinalIgnoreCase);
        var required = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var skipped = 0;

        foreach (var learnedPath in learnedPaths)
        {
            var path = (learnedPath ?? string.Empty).Trim();
            if (path.Length == 0)
            {
                skipped++;
                continue;
            }
            if (!seenPaths.Add(path)) continue;

            if (preparedRuleKeysByPath.TryGetValue(path, out var preparedKey) &&
                !string.IsNullOrWhiteSpace(preparedKey) &&
                (isAvailable(path) || readyRuleKeys.Contains(preparedKey)))
            {
                required.Add(preparedKey);
                continue;
            }
            if (references.TryGetValue(path, out var existingKey) && readyRuleKeys.Contains(existingKey))
            {
                required.Add(existingKey);
                continue;
            }
            skipped++;
        }

        return new InstallationLearningPlan
        {
            RequiredRuleKeys = required.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
            SkippedCount = skipped
        };
    }

    public static string PreferAvailableRepresentative(string currentPath, string candidatePath, Func<string, bool> exists)
    {
        if (!string.IsNullOrWhiteSpace(currentPath) && exists(currentPath)) return currentPath;
        if (!string.IsNullOrWhiteSpace(candidatePath) && exists(candidatePath)) return candidatePath;
        return currentPath;
    }
}
