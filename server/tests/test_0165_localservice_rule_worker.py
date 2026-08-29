import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Release0165RuleWorkerTests(unittest.TestCase):
    VERSION = "0.16.5"

    def read(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_rule_fragment_is_generation_only_and_no_longer_requires_admin(self):
        text = self.read("windows-agent/scripts/New-RuleFragment.ps1")
        self.assertNotIn("Assert-Administrator", text)
        self.assertIn("New-CIPolicyRule", text)
        self.assertIn("New-CIPolicy -MultiplePolicyFormat", text)
        self.assertNotIn("CiTool.exe", text)
        self.assertNotIn("ConvertFrom-CIPolicy", text)

    def test_program_has_dedicated_rule_worker_mode_without_normal_agent_services(self):
        text = self.read("windows-agent/src/AppGuard.Service/Program.cs")
        self.assertIn('--rule-worker', text)
        self.assertIn('AppControl Manager Rule Worker', text)
        self.assertIn('RuleWorkerService', text)
        self.assertIn('RuleWorkerClient', text)
        self.assertIn('if (ruleWorkerMode)', text)
        # Worker mode must branch before the normal agent DI registrations.
        self.assertLess(text.index('if (ruleWorkerMode)'), text.index('builder.Services.AddSingleton<ApiClient>()'))

    def test_rule_worker_contract_constrains_kind_and_paths(self):
        job = self.read("windows-agent/src/AppGuard.Service/RuleWorkerJob.cs")
        worker = self.read("windows-agent/src/AppGuard.Service/RuleWorkerService.cs")
        self.assertIn('RuleWorkerRequest', job)
        self.assertIn('RuleWorkerResult', job)
        self.assertIn('product', job)
        self.assertIn('hash', job)
        self.assertIn('RuleWorkerOperations.TryGetOutputFile', worker)
        self.assertIn('Path.GetFileName(request.InputFileName)', worker)
        self.assertIn('fragment.xml', job)
        self.assertNotIn('ScriptPath', job)
        self.assertNotIn('OutputPath', job)

    def test_policy_helper_routes_fragments_through_rule_worker_client(self):
        helper = self.read("windows-agent/src/AppGuard.Service/PolicyHelper.cs")
        client = self.read("windows-agent/src/AppGuard.Service/RuleWorkerClient.cs")
        self.assertIn('private readonly RuleWorkerClient _ruleWorker;', helper)
        self.assertIn('_ruleWorker.GenerateAsync(', helper)
        fragment_method = helper[helper.index('private async Task<BackgroundRuleFragmentResult> GenerateRuleFragmentCoreAsync'):]
        fragment_method = fragment_method[:fragment_method.index('public async Task<SupplementalResult> InstallMergedSupplementalAsync')]
        self.assertNotIn('New-RuleFragment.ps1', fragment_method)
        self.assertIn('request.json', client)
        self.assertIn('result.json', client)
        self.assertIn('workerOutputFileName', client)
        self.assertIn('File.Copy(sourcePath', client)

    def test_main_service_self_provisions_worker_for_0164_to_0165_managed_update(self):
        program = self.read("windows-agent/src/AppGuard.Service/Program.cs")
        provisioner = self.read("windows-agent/src/AppGuard.Service/RuleWorkerProvisioner.cs")
        self.assertIn("RuleWorkerProvisioner.EnsureInstalled()", program)
        self.assertIn("AppControlManagerRuleWorker", provisioner)
        self.assertIn("NT AUTHORITY\\LocalService", provisioner)
        self.assertIn("*S-1-5-19:(OI)(CI)(RX)", provisioner)
        grant_job = provisioner[provisioner.index("internal static void GrantJobAccess"):]
        self.assertIn("*S-1-5-19:(OI)(CI)(IO)(M)", grant_job)
        self.assertIn("ProtectStagedFile(canonicalJob, stagedInput)", grant_job)
        self.assertIn("ProtectStagedFile(canonicalJob, requestPath)", grant_job)
        self.assertIn('"sc.exe", "create"', provisioner)

    def test_install_update_and_uninstall_preserve_local_service_worker_lifecycle(self):
        installer = self.read("windows-agent/src/AppControlManager.Installer/Program.cs")
        upgrade = self.read("windows-agent/Upgrade-Agent.ps1")
        activation = self.read("windows-agent/scripts/Apply-AgentUpdate.ps1")
        uninstall = self.read("windows-agent/Uninstall-Agent.ps1")
        self.assertIn('AppControlManagerRuleWorker', installer)
        self.assertIn('StartMainAndVerify', installer)
        self.assertNotIn('EnsureRuleWorkerService', installer)
        for text in (upgrade, activation):
            self.assertIn('AppControlManagerRuleWorker', text)
            self.assertIn('Stop-Service', text)
            self.assertIn('Get-Service', text)
        self.assertIn('AppControlManagerRuleWorker', uninstall)
        self.assertIn('delete AppControlManagerRuleWorker', uninstall)
        self.assertIn('Stop-Service -Name $ruleWorkerServiceName', activation)
        self.assertNotIn('Start-Service -Name $ruleWorkerServiceName', activation)
        self.assertIn('Start-Service -Name $serviceName', activation)

    def test_0165_release_notes_preserve_worker_boundary_without_new_signed_binary(self):
        build = self.read("windows-agent/Build.ps1")
        workflow = self.read(".github/workflows/release.yml")
        self.assertNotIn('RuleWorker\\AppControlManager.RuleWorker.exe', build)
        self.assertNotIn('AppControlManager.RuleWorker.exe', workflow)
        notes = ROOT / "0.16.5-FEATURES.txt"
        self.assertTrue(notes.is_file())
        note_text = notes.read_text(encoding="utf-8")
        self.assertIn('Local Service', note_text)
        self.assertIn('0.16.2', note_text)
        self.assertIn('rollback', note_text.lower())


if __name__ == "__main__":
    unittest.main()
