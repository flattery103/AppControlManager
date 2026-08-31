import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT
    / "windows-agent"
    / "scripts"
    / "Test-AppControlManagerRecovery-RC13-v1.ps1"
)


class EndpointRecoveryScriptTests(unittest.TestCase):
    def script_text(self):
        self.assertTrue(SCRIPT.exists(), "endpoint recovery script is missing")
        return SCRIPT.read_text(encoding="utf-8")

    def test_has_versioned_recovery_and_crash_recovery_modes(self):
        text = self.script_text()
        self.assertIn("$testVersion = 'RC13-v1'", text)
        self.assertIn("[ValidateSet('Recovery', 'CrashRecovery')]", text)
        self.assertIn("[switch]$IncludeReboot", text)
        self.assertIn("[switch]$ResumeAfterReboot", text)

    def test_refuses_to_start_during_endpoint_work(self):
        text = self.script_text()
        for marker in (
            "update-status.json",
            "background-policy-state.json",
            "installation-mode.json",
            "Safety gate",
            "downloading",
            "preauthorizing",
            "processing",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_recovery_mode_stops_and_restores_each_component(self):
        text = self.script_text()
        self.assertIn("Stop-Service", text)
        self.assertIn("Start-Service", text)
        self.assertIn("Set-Service", text)
        self.assertIn("Ensure-TrayRunning.ps1", text)
        self.assertIn("Stop-Process", text)
        self.assertIn("Tray singleton after recovery", text)

    def test_crash_mode_verifies_new_service_process_and_restores_on_failure(self):
        text = self.script_text()
        self.assertIn("Invoke-ServiceCrashTest", text)
        self.assertIn("OriginalProcessId", text)
        self.assertIn("AutomaticCrashRecovery", text)
        self.assertIn("-TimeoutSeconds 75", text)
        self.assertIn("CrashRecovery requires -IncludeReboot", text)
        self.assertIn("$Mode -eq 'CrashRecovery' -or $currentFailures -eq 0", text)
        self.assertIn("Restore-Service", text)
        self.assertIn("finally", text)

    def test_reboot_continuation_is_one_time_and_self_removing(self):
        text = self.script_text()
        self.assertIn("$recoveryScriptPath = $PSCommandPath", text)
        self.assertIn("$scriptPath = $recoveryScriptPath", text)
        self.assertIn("-IncludeReboot -ResumeAfterReboot", text)
        self.assertIn("New-ScheduledTaskTrigger -AtLogOn", text)
        self.assertIn("Register-ScheduledTask", text)
        self.assertIn("Unregister-ScheduledTask", text)
        self.assertIn("Restart-Computer", text)
        self.assertIn("PreRebootReportPath", text)

    def test_finishes_with_health_validator_and_json_report(self):
        text = self.script_text()
        self.assertIn("Test-AppControlManagerEndpoint-RC13-v1.ps1", text)
        self.assertIn("ConvertTo-Json", text)
        self.assertIn("ExitCode", text)
        self.assertIn("$global:LASTEXITCODE", text)

    def test_documentation_marks_disruptive_modes_and_normal_directions(self):
        text = (ROOT / "docs" / "ENDPOINT-RECOVERY-VALIDATION.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("disposable test VM", text)
        self.assertIn("Test-AppControlManagerRecovery-RC13-v1.ps1", text)
        self.assertIn("-Mode Recovery", text)
        self.assertIn("-Mode CrashRecovery", text)
        self.assertIn("-IncludeReboot", text)


if __name__ == "__main__":
    unittest.main()
