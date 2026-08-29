using AppGuard.Core;

static void Equal<T>(T expected, T actual, string message)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new InvalidOperationException($"{message} Expected={expected}; Actual={actual}");
}

static void SequenceEqual(IEnumerable<string> expected, IEnumerable<string> actual, string message)
{
    var left = expected.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    var right = actual.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    if (!left.SequenceEqual(right, StringComparer.OrdinalIgnoreCase))
        throw new InvalidOperationException($"{message} Expected=[{string.Join(',', left)}]; Actual=[{string.Join(',', right)}]");
}

const string firefoxPath = @"C:\Program Files\Mozilla Firefox\firefox.exe";
const string deletedTempPath = @"C:\Users\user\AppData\Local\Temp\setup.tmp.dll";
const string firefoxRule = "product|mozilla|firefox";
const string deletedRule = "hash|deleted";

var mixed = InstallationLearningReconciler.Create(
    new[]
    {
        new InstallationLearnedFile(firefoxPath, 101),
        new InstallationLearnedFile(deletedTempPath, 102)
    },
    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        [firefoxPath] = firefoxRule,
        [deletedTempPath] = deletedRule
    },
    new[] { new LearningRuleReference { RecordId = 90, FilePath = deletedTempPath, RuleKey = deletedRule } },
    new HashSet<string>(StringComparer.OrdinalIgnoreCase),
    path => path.Equals(firefoxPath, StringComparison.OrdinalIgnoreCase));
SequenceEqual(new[] { firefoxRule }, mixed.RequiredRuleKeys, "A queued stale reference must not make a deleted file mandatory.");
Equal(1, mixed.SkippedCount, "The deleted unprepared file must be counted as skipped.");

var reusable = InstallationLearningReconciler.Create(
    new[] { new InstallationLearnedFile(deletedTempPath, 202) },
    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
    new[] { new LearningRuleReference { RecordId = 202, FilePath = deletedTempPath, RuleKey = deletedRule } },
    new HashSet<string>(new[] { deletedRule }, StringComparer.OrdinalIgnoreCase),
    _ => false);
SequenceEqual(new[] { deletedRule }, reusable.RequiredRuleKeys, "A valid cached Ready fragment may cover a file that has since disappeared.");
Equal(0, reusable.SkippedCount, "A reusable Ready fragment must not also be reported as skipped.");

var crossSession = InstallationLearningReconciler.Create(
    new[] { new InstallationLearnedFile(deletedTempPath, 303) },
    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
    new[] { new LearningRuleReference { RecordId = 202, FilePath = deletedTempPath, RuleKey = deletedRule } },
    new HashSet<string>(new[] { deletedRule }, StringComparer.OrdinalIgnoreCase),
    _ => false);
Equal(0, crossSession.RequiredRuleKeys.Count, "A Ready fragment from another learning session must not authorize a reused path.");
Equal(1, crossSession.SkippedCount, "A cross-session same-path reference must remain skipped.");

var unusable = InstallationLearningReconciler.Create(
    new[] { new InstallationLearnedFile(deletedTempPath, 404) },
    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
    new[] { new LearningRuleReference { RecordId = 404, FilePath = deletedTempPath, RuleKey = deletedRule } },
    new HashSet<string>(StringComparer.OrdinalIgnoreCase),
    _ => false);
Equal(0, unusable.RequiredRuleKeys.Count, "A session with only a stale queued reference must have zero safe rules.");
Equal(1, unusable.SkippedCount, "A session with only a stale queued reference must retain its skipped count.");

var available = new HashSet<string>(new[] { firefoxPath }, StringComparer.OrdinalIgnoreCase);
var representative = InstallationLearningReconciler.PreferAvailableRepresentative(
    deletedTempPath,
    firefoxPath,
    available.Contains);
Equal(firefoxPath, representative, "A current valid equivalent file must replace a deleted representative path.");

Console.WriteLine("AppGuard.Core behavior tests passed (5 cases).");
