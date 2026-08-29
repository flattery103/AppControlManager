using AppGuard.Core;

internal static class WorkerOutputSnapshotBehavior
{
    public static void Run()
    {
        var root = Path.Combine(Path.GetTempPath(), $"acm-worker-output-{Guid.NewGuid():N}");
        var job = Path.Combine(root, Guid.NewGuid().ToString("N"));
        var protectedDirectory = Path.Combine(root, "protected");
        Directory.CreateDirectory(job);
        Directory.CreateDirectory(protectedDirectory);
        var output = Path.Combine(job, "policy.xml");
        var bytes = "stable worker output bytes"u8.ToArray();
        File.WriteAllBytes(output, bytes);
        try
        {
            var snapshot = WorkerOutputSnapshot.CopyExactToProtected(output, output, protectedDirectory);
            try
            {
                if (!File.ReadAllBytes(snapshot).SequenceEqual(bytes))
                    throw new InvalidOperationException("mutation: snapshot copies from a different handle");
            }
            finally { File.Delete(snapshot); }

            var wrongExpectedPath = Path.Combine(job, "fragment.xml");
            try
            {
                WorkerOutputSnapshot.CopyExactToProtected(output, wrongExpectedPath, protectedDirectory);
                throw new InvalidOperationException("mutation: final handle path is not bound to the fixed job output");
            }
            catch (InvalidDataException) { }

            TryRejectSymbolicLink(job, output, protectedDirectory);
        }
        finally { Directory.Delete(root, true); }
    }

    private static void TryRejectSymbolicLink(string job, string target, string protectedDirectory)
    {
        var link = Path.Combine(job, "fragment.xml");
        try { File.CreateSymbolicLink(link, target); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }
        try
        {
            WorkerOutputSnapshot.CopyExactToProtected(link, link, protectedDirectory);
            throw new InvalidOperationException("mutation: reparse-point output is followed and copied");
        }
        catch (InvalidDataException) { }
    }
}
