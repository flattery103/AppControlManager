namespace AppGuard.Service;

public sealed record EphemeralEvidence(
    string FilePath,
    bool ActiveInstallationSession,
    bool SignatureValid,
    bool SignerMatchesInstaller,
    bool ParentInInstallerChain,
    bool KnownExtractionPattern,
    bool ShortLivedOrUnavailable,
    bool DurableCoverageExists,
    bool ExplicitlyBlocked,
    bool SignerConflict,
    bool PersistentExecution);

public sealed record EphemeralDisposition(string Disposition, string Reason)
{
    public static readonly EphemeralDisposition Unknown = new("unknown", "Insufficient evidence to classify temporary execution.");
}

public static class EphemeralExecutionClassifier
{
    public static EphemeralDisposition Classify(EphemeralEvidence evidence)
    {
        if (!evidence.ActiveInstallationSession || !IsRecognizedTempPath(evidence.FilePath))
            return EphemeralDisposition.Unknown;
        if (evidence.ExplicitlyBlocked || evidence.SignerConflict || evidence.PersistentExecution || !evidence.SignatureValid)
            return new EphemeralDisposition("security_relevant", "Temporary execution has a conflicting or persistent security signal.");

        var corroboratingSignals = 0;
        if (evidence.SignerMatchesInstaller) corroboratingSignals++;
        if (evidence.ParentInInstallerChain) corroboratingSignals++;
        if (evidence.KnownExtractionPattern) corroboratingSignals++;
        if (evidence.ShortLivedOrUnavailable) corroboratingSignals++;
        if (evidence.DurableCoverageExists) corroboratingSignals++;
        if (corroboratingSignals >= 2 && evidence.DurableCoverageExists)
            return new EphemeralDisposition("expected_ephemeral", "Signed installation-session extraction has durable application coverage.");
        return EphemeralDisposition.Unknown;
    }

    private static bool IsRecognizedTempPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        string full;
        try { full = Path.GetFullPath(value); } catch { return false; }
        var roots = new[] { Path.GetTempPath(), Environment.GetEnvironmentVariable("TEMP"),
            Environment.GetEnvironmentVariable("TMP"), @"C:\Windows\Temp" }
            .Where(x => !string.IsNullOrWhiteSpace(x));
        return roots.Any(root =>
        {
            var normalizedRoot = Path.GetFullPath(root!).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var rootWithSeparator = normalizedRoot + Path.DirectorySeparatorChar;
            return string.Equals(full, normalizedRoot, StringComparison.OrdinalIgnoreCase) ||
                full.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase);
        });
    }
}
