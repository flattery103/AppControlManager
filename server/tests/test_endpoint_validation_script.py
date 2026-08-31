import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT
    / "windows-agent"
    / "scripts"
    / "Test-AppControlManagerEndpoint-1.0-v1.ps1"
)


class EndpointValidationScriptTests(unittest.TestCase):
    def script_text(self):
        self.assertTrue(SCRIPT.exists(), "endpoint validation script is missing")
        return SCRIPT.read_text(encoding="utf-8")

    def test_exposes_safe_health_and_functional_modes(self):
        text = self.script_text()
        self.assertIn("$validatorVersion = '1.0-v1'", text)
        self.assertIn('endpoint validation $validatorVersion ($Mode)', text)
        self.assertIn("[ValidateSet('Health', 'Functional')]", text)
        self.assertIn("[string]$Mode = 'Health'", text)
        self.assertNotIn("Destructive", text)

    def test_health_mode_covers_endpoint_release_contract(self):
        text = self.script_text()
        required_contracts = (
            "AppControlManagerRuleWorker",
            "AppControlManager.Tray.exe",
            "Get-AuthenticodeSignature",
            "update-status.json",
            "background-policy-state.json",
            "CiTool.exe",
            "CodeIntegrity/Operational",
            "agent-service.log",
            "Get-PSDrive",
            "qfailure",
            "qfailureflag",
            "restart/10000/restart/30000/restart/60000",
            "86400",
        )
        for contract in required_contracts:
            with self.subTest(contract=contract):
                self.assertIn(contract, text)
        self.assertIn('Health endpoint returned 200 from $serverUrl.', text)
        self.assertIn("($recoveryDelays -join '/') -eq '10000/30000/60000'", text)
        self.assertIn("$allRecoveryActions.Count -eq 3", text)
        self.assertNotIn('HTTPS health endpoint returned 200', text)

    def test_functional_mode_only_repairs_services_and_tray(self):
        text = self.script_text()
        self.assertIn("Set-Service", text)
        self.assertIn("Start-Service", text)
        self.assertIn("Ensure-TrayRunning.ps1", text)
        recovery = text[text.index("function Invoke-SafeRecovery"):text.index(
            'Write-Host "AppControl Manager endpoint validation'
        )]
        self.assertIn("$trayRecoveryExitCode", recovery)
        self.assertIn("$trayAfterRecovery", recovery)
        forbidden_mutations = (
            "remove-policy",
            "Uninstall-Agent.ps1",
            "Start-LearningMode.ps1",
            "Force-Enforcement.ps1",
            "New-DenyPolicyForFile.ps1",
        )
        for mutation in forbidden_mutations:
            with self.subTest(mutation=mutation):
                self.assertNotIn(mutation, text)

    def test_writes_machine_readable_report_and_sets_exit_code(self):
        text = self.script_text()
        self.assertIn("ConvertTo-Json", text)
        self.assertIn("-OutputPath", text)
        self.assertIn("Results = $results.ToArray()", text)
        self.assertNotIn("Results = @($results)", text)
        self.assertIn("$global:LASTEXITCODE", text)
        self.assertIn("ExitCode", text)

    def test_documentation_contains_normal_run_directions(self):
        text = (
            ROOT / "docs" / "ENDPOINT-VALIDATION.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Windows PowerShell as Administrator", text)
        self.assertIn("Test-AppControlManagerEndpoint-1.0-v1.ps1", text)
        self.assertIn("-Mode Health", text)
        self.assertIn("-Mode Functional", text)
        self.assertIn("-OutputPath", text)


if __name__ == "__main__":
    unittest.main()
