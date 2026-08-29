import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class Release0180RuleWorkerTests(unittest.TestCase):
    def read(self, relative_path):
        path = ROOT / relative_path
        return path.read_text(encoding="utf-8") if path.is_file() else ""

    def test_worker_startup_cleanup_is_old_failed_or_unpublished_only(self):
        worker = self.read("windows-agent/src/AppGuard.Service/RuleWorkerService.cs")
        self.assertIn("CleanupStaleJobs", worker)
        self.assertIn("TimeSpan.FromDays(7)", worker)
        cleanup = worker[worker.index("CleanupStaleJobs"):]
        self.assertIn("RuleWorkerJobsDirectory", cleanup)
        self.assertIn('"result.json"', cleanup)
        self.assertIn('"request.json"', cleanup)
        self.assertIn("!result.Success", cleanup)
        self.assertIn("!File.Exists(requestPath) && !File.Exists(resultPath)", cleanup)
        self.assertNotIn("RuleFragmentDirectory", cleanup)
        self.assertNotIn("PolicyDirectory", cleanup)

    def test_worker_operation_map_is_closed_and_fixes_each_output_name(self):
        job = self.read("windows-agent/src/AppGuard.Service/RuleWorkerJob.cs")
        entries = dict(re.findall(r'\["([a-z_]+)"\]\s*=\s*"([a-z.]+)"', job))
        self.assertEqual(
            entries,
            {
                "product": "fragment.xml",
                "hash": "fragment.xml",
                "primary_allow": "policy.xml",
                "deny_policy": "policy.xml",
            },
        )

    def test_worker_request_contains_only_job_operation_and_basename_input(self):
        job = self.read("windows-agent/src/AppGuard.Service/RuleWorkerJob.cs")
        request = job[job.index("class RuleWorkerRequest"):job.index("class RuleWorkerResult")]
        json_names = set(re.findall(r'JsonPropertyName\("([^"]+)"\)', request))
        self.assertEqual(json_names, {"job_id", "operation", "input_file_name"})
        for forbidden in ("script", "output", "install", "credential", "argument", "device_key"):
            self.assertNotIn(forbidden, request.lower())

    def test_worker_result_carries_validated_operation_mode_and_file_metadata(self):
        job = self.read("windows-agent/src/AppGuard.Service/RuleWorkerJob.cs")
        result = job[job.index("class RuleWorkerResult"):]
        for json_name in (
            "operation", "rule_count", "rule_mode", "elapsed_seconds", "error",
            "file_path", "sha256", "publisher", "product_name", "file_version",
        ):
            self.assertIn(f'JsonPropertyName("{json_name}")', result)

    def test_worker_validates_identity_containment_fixed_output_and_result(self):
        worker = self.read("windows-agent/src/AppGuard.Service/RuleWorkerService.cs")
        client = self.read("windows-agent/src/AppGuard.Service/RuleWorkerClient.cs")
        self.assertIn('Guid.TryParseExact(request.JobId, "N"', worker)
        self.assertIn("Path.GetFileName(request.InputFileName)", worker)
        self.assertIn("StartsWith(root, StringComparison.OrdinalIgnoreCase)", worker)
        self.assertIn("RuleWorkerOperations.TryGetOutputFile", worker)
        self.assertIn("RuleWorkerOperations.TryGetOutputFile", client)
        self.assertIn("result.Operation.Equals(request.Operation", client)
        self.assertIn("result.RuleCount <= 0", client)
        validator = self.read("windows-agent/src/AppGuard.Core/WorkerPolicyValidator.cs")
        self.assertIn("XDocument.Load", validator)

    def test_local_system_snapshots_before_validation_and_publishes_validated_bytes(self):
        client = self.read("windows-agent/src/AppGuard.Service/RuleWorkerClient.cs")
        consume = client[client.index('RejectReparsePoint(jobDirectory, "job directory")'):client.index("result.FilePath = sourcePath")]
        for required in (
            "WorkerOutputSnapshot.CopyExactToProtected", "WorkerPolicyValidator.ValidateAndNormalizeFile(protectedSnapshot",
            "File.Move(protectedSnapshot, canonical",
        ):
            self.assertIn(required, consume)
        snapshot = consume.index("WorkerOutputSnapshot.CopyExactToProtected")
        validate = consume.index("WorkerPolicyValidator.ValidateAndNormalizeFile(protectedSnapshot")
        publish = consume.index("File.Move(protectedSnapshot, canonical")
        self.assertLess(snapshot, validate)
        self.assertLess(validate, publish)
        self.assertNotIn("File.Copy(workerOutput, canonical", consume)
        self.assertIn('RejectReparsePoint(canonicalDirectory, "protected output directory")', client)
        self.assertIn("Path.GetDirectoryName(canonical)", client)

    def test_local_system_rejects_forged_operation_semantics_and_identity(self):
        validation = self.read("windows-agent/src/AppGuard.Core/WorkerPolicyValidator.cs")
        self.assertIn("private static string ValidateOperationSemantics", validation)
        for semantic_node in ("Allow", "AllowedSigner", "Deny", "DeniedSigner"):
            self.assertIn(f'ns + "{semantic_node}"', validation)
        self.assertIn('ns + "PolicyID"', validation)
        self.assertIn('ns + "BasePolicyID"', validation)
        self.assertIn("PolicyID and BasePolicyID must match", validation)
        self.assertIn('Attribute("PolicyType")', validation)
        self.assertIn('"Base Policy"', validation)
        self.assertIn("Unexpected policy content", validation)
        self.assertIn('ns + "PlatformID"', validation)
        self.assertIn('ns + "HvciOptions"', validation)
        self.assertIn('"ExceptDenyRule"', validation)
        self.assertIn('"ExceptAllowRule"', validation)
        self.assertIn('ns + "FileRuleRef"', validation)
        self.assertIn('ns + "FileAttribRef"', validation)
        self.assertIn("AllHashRulesMatchExpectedInput", validation)
        self.assertIn("Unexpected rule option", validation)
        self.assertIn('"primary_allow"', validation)
        self.assertIn('"deny_policy"', validation)
        allowed_options = validation[validation.index("AllowedWorkerRuleOptions"):validation.index("public static string ValidateAndNormalizeFile")]
        self.assertNotIn("Allow Supplemental Policies", allowed_options)
        self.assertNotIn("Update Policy No Reboot", allowed_options)
        self.assertNotIn("Boot Audit on Failure", allowed_options)

    def test_trusted_input_identity_and_stable_handle_are_behavior_tested_on_windows(self):
        client = self.read("windows-agent/src/AppGuard.Service/RuleWorkerClient.cs")
        core_validator = self.read("windows-agent/src/AppGuard.Core/WorkerPolicyValidator.cs")
        stable_snapshot = self.read("windows-agent/src/AppGuard.Core/WorkerOutputSnapshot.cs")
        behavior = self.read("windows-agent/tests/AppGuard.Core.BehaviorTests/WorkerPolicyValidationBehavior.cs")
        snapshot_behavior = self.read("windows-agent/tests/AppGuard.Core.BehaviorTests/WorkerOutputSnapshotBehavior.cs")
        for mutation in (
            "unrelated hash is accepted", "unrelated ProductName is accepted",
            "unrelated signer is accepted", "allow operation accepts deny semantics",
            "deny operation accepts allow semantics", "malformed policy is accepted",
        ):
            self.assertIn(mutation, behavior)
        self.assertIn("exact hash identity", behavior)
        self.assertIn("exact ProductName and signer identity", behavior)
        self.assertIn("exact FilePublisher file/version and signer identity", behavior)
        self.assertIn("final handle path is not bound", snapshot_behavior)
        self.assertIn("reparse-point output is followed", snapshot_behavior)

        setup = client[client.index("File.Copy(sourcePath, stagedInput"):client.index("publishedToWorker = true")]
        self.assertIn("WorkerPolicyInputIdentity.FromFile(stagedInput)", setup)
        self.assertLess(setup.index("WorkerPolicyInputIdentity.FromFile(stagedInput)"), setup.index("GrantJobAccess"))
        consume = client[client.index("if (!result.Operation.Equals"):client.index("result.FilePath = sourcePath")]
        self.assertIn("WorkerOutputSnapshot.CopyExactToProtected(workerOutput, workerOutput", consume)
        self.assertIn("WorkerPolicyValidator.ValidateAndNormalizeFile(protectedSnapshot", consume)
        self.assertNotIn("ValidateAndNormalizeFile(protectedSnapshot, operation, result.RuleMode", consume)
        self.assertIn("result.RuleMode.Equals(validatedRuleMode", consume)
        self.assertNotIn('RejectReparsePoint(workerOutput, "generated output")', consume)
        self.assertIn("GetFinalPathNameByHandle", stable_snapshot)
        self.assertIn("FILE_FLAG_OPEN_REPARSE_POINT", stable_snapshot)
        self.assertIn("expected.ExpectedPolicyHashes", core_validator)
        self.assertIn("expected.ProductName", core_validator)
        self.assertIn("expected.PublisherNames", core_validator)
        self.assertIn("expected.SignerTbsHashes", core_validator)

    def test_installed_policy_behavior_test_is_wired_into_windows_workflows(self):
        test_script = self.read(".github/tests/Test-InstalledPolicyValidation.ps1")
        helper = self.read("windows-agent/scripts/GeneratedPolicyValidation.ps1")
        installer = self.read("windows-agent/scripts/Install-GeneratedPolicy.ps1")
        for mutation in (
            "empty policy list accepted", "multiple matching policies accepted",
            "missing enforcement property accepted", "missing authorization property accepted",
            "string enforcement value accepted as true", "false authorization accepted",
        ):
            self.assertIn(mutation, test_script)
        self.assertIn("Assert-InstalledGeneratedPolicy", helper)
        self.assertIn("Assert-InstalledGeneratedPolicy", installer)
        for workflow in (".github/workflows/build-windows.yml", ".github/workflows/release.yml"):
            self.assertIn("Test-InstalledPolicyValidation.ps1", self.read(workflow))

    def test_worker_rejects_reparse_points_at_both_sides_of_file_boundary(self):
        worker = self.read("windows-agent/src/AppGuard.Service/RuleWorkerService.cs")
        client = self.read("windows-agent/src/AppGuard.Service/RuleWorkerClient.cs")
        self.assertIn("FileAttributes.ReparsePoint", worker)
        self.assertIn("FileAttributes.ReparsePoint", client)

    def test_staging_precedes_per_job_worker_write_access(self):
        client = self.read("windows-agent/src/AppGuard.Service/RuleWorkerClient.cs")
        provisioner = self.read("windows-agent/src/AppGuard.Service/RuleWorkerProvisioner.cs")
        setup = client[client.index("var jobId ="):client.index("_log.Write($\"rule-worker queued")]
        self.assertIn("RejectReparsePoint(AppGuardPaths.RuleWorkerJobsDirectory", setup)
        self.assertIn("RuleWorkerProvisioner.GrantJobAccess(jobDirectory, stagedInput, requestPath)", setup)
        self.assertLess(setup.index("RejectReparsePoint(AppGuardPaths.RuleWorkerJobsDirectory"), setup.index("Directory.CreateDirectory(jobDirectory)"))
        self.assertLess(setup.index("File.Copy(sourcePath, stagedInput"), setup.index("RuleWorkerProvisioner.GrantJobAccess(jobDirectory, stagedInput, requestPath)"))
        self.assertLess(setup.index("WriteJsonAtomicAsync(requestPath"), setup.index("RuleWorkerProvisioner.GrantJobAccess(jobDirectory, stagedInput, requestPath)"))
        self.assertIn('"*S-1-5-19:(OI)(CI)(RX)"', provisioner)
        self.assertIn("GrantJobAccess", provisioner)
        self.assertIn('"*S-1-5-19:(OI)(CI)(IO)(M)"', provisioner[provisioner.index("GrantJobAccess"):])

    def test_provisioning_rejects_worker_controlled_reparse_objects_before_writes(self):
        provisioner = self.read("windows-agent/src/AppGuard.Service/RuleWorkerProvisioner.cs")
        ensure = provisioner[provisioner.index("public static void EnsureInstalled"):provisioner.index("internal static void GrantJobAccess")]
        root_guard = ensure.index('RejectExistingReparsePoint(AppGuardPaths.RuleWorkerDirectory')
        root_create = ensure.index('Directory.CreateDirectory(AppGuardPaths.RuleWorkerDirectory)')
        jobs_guard = ensure.index('RejectExistingReparsePoint(AppGuardPaths.RuleWorkerJobsDirectory')
        jobs_create = ensure.index('Directory.CreateDirectory(AppGuardPaths.RuleWorkerJobsDirectory)')
        log_guard = ensure.index('RejectExistingReparsePoint(AppGuardPaths.RuleWorkerLog')
        log_write = ensure.index('File.WriteAllText(AppGuardPaths.RuleWorkerLog')
        self.assertLess(root_guard, root_create)
        self.assertLess(jobs_guard, jobs_create)
        self.assertLess(log_guard, log_write)
        self.assertIn("LinkTarget", provisioner)

    def test_request_and_result_json_reject_unknown_fields(self):
        for relative_path in (
            "windows-agent/src/AppGuard.Service/RuleWorkerClient.cs",
            "windows-agent/src/AppGuard.Service/RuleWorkerService.cs",
        ):
            text = self.read(relative_path)
            self.assertIn("JsonUnmappedMemberHandling.Disallow", text)

    def test_local_service_powershell_is_generation_only(self):
        for relative_path in (
            "windows-agent/scripts/New-RuleFragment.ps1",
            "windows-agent/scripts/New-WorkerPolicy.ps1",
        ):
            text = self.read(relative_path)
            self.assertNotIn("Assert-Administrator", text)
            self.assertNotIn("CiTool", text)
            self.assertNotIn("ConvertFrom-CIPolicy", text)
            self.assertNotIn("Merge-CIPolicy", text)
            self.assertNotIn("Set-CIPolicyIdInfo", text)
            self.assertIn("New-CIPolicy", text)

    def test_foreground_generation_preserves_allow_and_deny_fallbacks(self):
        worker_script = self.read("windows-agent/scripts/New-WorkerPolicy.ps1")
        self.assertIn("SpecificFileNameLevel ProductName", worker_script)
        self.assertIn("Test-AppGuardProductFamilyCandidate", worker_script)
        self.assertIn("-Fallback SignedVersion,Publisher,Hash", worker_script)
        self.assertIn("-Level Hash", worker_script)
        self.assertIn("-Deny", worker_script)
        self.assertIn("Fall through to conservative per-file deny", worker_script)

    def test_local_system_installer_owns_post_processing_and_verification(self):
        installer = self.read("windows-agent/scripts/Install-GeneratedPolicy.ps1")
        verification = self.read("windows-agent/scripts/GeneratedPolicyValidation.ps1")
        self.assertIn("Assert-Administrator", installer)
        self.assertIn("GetFullPath", installer)
        self.assertIn("$script:PolicyDir", installer)
        self.assertIn("Set-CIPolicyIdInfo", installer)
        self.assertIn("SupplementsBasePolicyID", installer)
        self.assertIn("Set-RuleOption", installer)
        self.assertIn("ConvertFrom-CIPolicy", installer)
        self.assertIn("CiTool.exe --update-policy", installer)
        self.assertIn("CiTool.exe --refresh", installer)
        self.assertIn("CiTool.exe -lp -json", installer)
        self.assertIn("Assert-InstalledGeneratedPolicy", installer)
        self.assertIn("IsCurrentlyEnforced", verification)
        self.assertIn("IsAuthorized", verification)

    def test_deny_merge_and_identity_are_local_system_only_and_fail_closed(self):
        worker = self.read("windows-agent/scripts/New-WorkerPolicy.ps1")
        installer = self.read("windows-agent/scripts/Install-GeneratedPolicy.ps1")
        self.assertNotIn("AllowAll.xml", worker)
        self.assertNotIn("Merge-CIPolicy", worker)
        self.assertNotIn("Set-CIPolicyIdInfo", worker)
        self.assertIn("if($Operation -eq 'deny_policy')", installer)
        deny_install = installer[installer.index("if($Operation -eq 'deny_policy')"):installer.index("Set-CIPolicyVersion")]
        self.assertIn("AllowAll.xml", deny_install)
        self.assertIn("Merge-CIPolicy", deny_install)
        self.assertLess(deny_install.index("Merge-CIPolicy"), deny_install.index("Set-CIPolicyIdInfo"))
        self.assertNotIn("catch {}", deny_install)
        for option in ("3 -Delete", "11", "16"):
            self.assertIn(f"Set-RuleOption -FilePath $xml -Option {option}", deny_install)

    def test_install_verification_rejects_empty_multiple_and_incomplete_matches(self):
        installer = self.read("windows-agent/scripts/Install-GeneratedPolicy.ps1")
        verification = self.read("windows-agent/scripts/GeneratedPolicyValidation.ps1")
        self.assertIn("Assert-InstalledGeneratedPolicy -Policies $listing -PolicyId $policyId", installer)
        self.assertIn("$matchingPolicies.Count -ne 1", verification)
        self.assertNotIn("Select-Object -First", verification)
        self.assertNotIn("$enforced=$true", verification)
        self.assertNotIn("$authorized=$true", verification)
        self.assertIn("IsCurrentlyEnforced property is missing", verification)
        self.assertIn("IsAuthorized property is missing", verification)
        self.assertIn("$installed.IsCurrentlyEnforced -isnot [bool]", verification)
        self.assertIn("$installed.IsCurrentlyEnforced -ne $true", verification)
        self.assertIn("$installed.IsAuthorized -isnot [bool]", verification)
        self.assertIn("$installed.IsAuthorized -ne $true", verification)

    def test_foreground_approval_and_deny_use_worker_then_local_system_installer(self):
        helper = self.read("windows-agent/src/AppGuard.Service/PolicyHelper.cs")
        approval = helper[helper.index("public async Task<SupplementalResult> ApproveFilesAsync"):helper.index("public async Task<T> RunSerializedBackgroundAsync")]
        deny = helper[helper.index("public async Task<SupplementalResult> BlockFileAsync"):helper.index("public async Task RemovePolicyAsync")]
        for section, operation in ((approval, "primary_allow"), (deny, "deny_policy")):
            self.assertIn(f'GenerateAsync("{operation}"', section)
            self.assertIn("Install-GeneratedPolicy.ps1", section)
            self.assertLess(section.index("GenerateAsync("), section.index("Install-GeneratedPolicy.ps1"))
        self.assertNotIn("New-PrimaryApprovalPolicy.ps1", approval)
        self.assertNotIn("New-DenyPolicyForFile.ps1", deny)

    def test_foreground_serialization_priority_and_background_bundle_are_preserved(self):
        helper = self.read("windows-agent/src/AppGuard.Service/PolicyHelper.cs")
        approval = helper[helper.index("public async Task<SupplementalResult> ApproveFilesAsync"):helper.index("public async Task<T> RunSerializedBackgroundAsync")]
        deny = helper[helper.index("public async Task<SupplementalResult> BlockFileAsync"):helper.index("public async Task RemovePolicyAsync")]
        self.assertIn("_policyGenerationGate.WaitAsync", approval)
        self.assertIn("_policyGenerationGate.WaitAsync", deny)
        self.assertIn("Interlocked.Increment(ref _foregroundWaiters)", approval)
        self.assertIn("Interlocked.Increment(ref _foregroundWaiters)", deny)
        self.assertIn("QueueBackgroundBundle", approval)


if __name__ == "__main__":
    unittest.main()
