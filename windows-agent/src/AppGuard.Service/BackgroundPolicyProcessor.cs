using AppGuard.Core;

namespace AppGuard.Service;

public sealed class BackgroundPolicyProcessor
{
    private readonly BackgroundPolicyStore _store;
    private readonly PolicyHelper _policies;
    private readonly ApiClient _api;
    private readonly FileLogger _log;

    public BackgroundPolicyProcessor(BackgroundPolicyStore store, PolicyHelper policies, ApiClient api, FileLogger log)
    {
        _store = store;
        _policies = policies;
        _api = api;
        _log = log;
    }

    public BackgroundPolicyQueueStatus QueueStatus() => _store.QueueStatus();

    public async Task<bool> ProcessOneAsync(CancellationToken ct)
    {
        if (_policies.ForegroundPending) return false;

        var rule = _store.ClaimNextRule();
        if (rule is not null)
        {
            try
            {
                if (_policies.ForegroundPending)
                {
                    _store.RequeueRule(rule.CacheKey, "Foreground policy generation became pending before background work started.");
                    return false;
                }
                var result = await _policies.GenerateRuleFragmentAsync(rule, ct);
                _store.MarkRuleReady(rule.CacheKey, result.FragmentXmlPath, rule.MinimumFileVersion);
                _log.Write($"background-rule ready key={rule.CacheKey} kind={rule.Kind} elapsed={result.ElapsedSeconds:F1}s");
            }
            catch (FileNotFoundException ex)
            {
                _store.MarkRuleExpired(rule.CacheKey, "Representative expired before it could be preserved.");
                _log.Write($"background-rule expired key={rule.CacheKey}: {ex.Message}");
            }
            catch (Exception ex)
            {
                _store.MarkRuleFailed(rule.CacheKey, ex.Message);
                _log.Write($"background-rule failed key={rule.CacheKey}: {ex.Message}");
            }
            return true;
        }

        var bundle = _store.ClaimReadyBundle();
        if (bundle is null) return false;
        try
        {
            var rules = _store.RulesForKeys(bundle.RequiredRuleKeys);
            var fragments = rules
                .Where(x => x.Status == BackgroundPolicyStatuses.Ready && !string.IsNullOrWhiteSpace(x.FragmentXmlPath))
                .Select(x => x.FragmentXmlPath!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (fragments.Length != bundle.RequiredRuleKeys.Count)
                throw new InvalidOperationException("Background bundle was claimed before all fragment paths were ready.");

            var result = await _policies.InstallMergedSupplementalAsync(bundle.RequestId, fragments, ct);
            _store.MarkBundleInstalled(bundle.RequestId, result.PolicyId);
            await _api.ReportBackgroundPolicyAsync(ToReport(bundle, "installed", result.PolicyId, "Background application coverage installed."), ct);
            _log.Write($"background-bundle installed request={bundle.RequestId} policy={result.PolicyId} fragments={fragments.Length}");
        }
        catch (Exception ex)
        {
            _store.MarkBundleFailed(bundle.RequestId, ex.Message);
            try
            {
                await _api.ReportBackgroundPolicyAsync(ToReport(bundle, "failed", null, ex.Message), ct);
            }
            catch (Exception reportEx)
            {
                _log.Write("background report failed: " + reportEx.Message);
            }
            _log.Write($"background-bundle failed request={bundle.RequestId}: {ex.Message}");
        }
        return true;
    }

    private static BackgroundPolicyReport ToReport(BackgroundBundleJob bundle, string status, string? policyId, string detail)
        => new()
        {
            RequestId = bundle.RequestId,
            ScopedPolicyId = bundle.ScopedPolicyId,
            Status = status,
            PolicyId = policyId,
            Detail = detail,
            Components = bundle.Members.Select(x => new ApprovalComponent
            {
                FilePath = x.FilePath,
                Sha256 = x.Sha256,
                Publisher = x.Publisher,
                ProductName = x.ProductName,
                FileVersion = x.FileVersion
            }).ToList()
        };
}
