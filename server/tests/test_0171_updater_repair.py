import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class Release0171UpdaterRepairTests(unittest.TestCase):
    def read(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_activation_uses_the_hash_verified_staged_helper(self):
        updater = self.read("windows-agent/src/AppGuard.Service/AgentUpdater.cs")
        launch = updater[updater.index("public void LaunchActivation"):]
        launch = launch[:launch.index("public async Task CleanupPreviousTrustAsync")]

        self.assertIn(
            'Path.Combine(update.StagingPath, "scripts", "Apply-AgentUpdate.ps1")',
            launch,
        )
        self.assertNotIn("AppGuardPaths.ScriptsDirectory", launch)

        validation = updater[updater.index("private static void ValidateStaging"):]
        self.assertIn("requiredManifestPaths", validation)
        self.assertIn('"scripts/Apply-AgentUpdate.ps1"', validation)
        self.assertIn("manifestPaths.Contains", validation)

    def test_activation_delegates_rule_worker_provisioning_to_the_main_service(self):
        activation = self.read("windows-agent/scripts/Apply-AgentUpdate.ps1")

        self.assertNotIn("function Ensure-RuleWorker", activation)
        self.assertNotIn("sc.exe config", activation)
        self.assertNotIn("sc.exe create", activation)
        self.assertNotIn("Start-Service -Name $ruleWorkerServiceName", activation)
        self.assertIn("Start-Service -Name $serviceName", activation)
        self.assertIn("Wait-ServiceStable $ruleWorkerServiceName", activation)

    def test_activation_timeout_reports_windows_service_state_and_exit_codes(self):
        activation = self.read("windows-agent/scripts/Apply-AgentUpdate.ps1")

        self.assertIn("function Get-ServiceDiagnostic", activation)
        self.assertIn("Get-CimInstance Win32_Service", activation)
        self.assertIn("ServiceSpecificExitCode", activation)
        self.assertIn("Get-ServiceDiagnostic $serviceName", activation)
        self.assertIn("Get-ServiceDiagnostic $ruleWorkerServiceName", activation)

    def test_manual_upgrade_avoids_the_same_powershell_native_argument_failure(self):
        upgrade = self.read("windows-agent/Upgrade-Agent.ps1")

        self.assertNotIn("sc.exe config", upgrade)
        self.assertNotIn("sc.exe create", upgrade)
        self.assertNotIn("Start-Service $ruleWorkerServiceName", upgrade)
        self.assertIn("Start-Service AppControlManager", upgrade)
        self.assertIn("Get-Service $ruleWorkerServiceName", upgrade)

    def test_manual_first_install_also_delegates_rule_worker_to_main_service(self):
        install = self.read("windows-agent/Install-Agent.ps1")

        self.assertNotIn("$workerBin", install)
        self.assertNotIn("sc.exe create $ruleWorkerServiceName", install)
        self.assertNotIn("Start-Service $ruleWorkerServiceName", install)
        self.assertIn("Start-Service AppControlManager", install)
        self.assertIn("Get-Service $ruleWorkerServiceName", install)

    def test_signed_installer_repairs_existing_endpoint_without_reenrollment(self):
        installer = self.read(
            "windows-agent/src/AppControlManager.Installer/Program.cs"
        )

        self.assertIn("ExistingInstallDetected", installer)
        self.assertIn("RepairExistingAsync", installer)
        self.assertIn("BackupExistingInstall", installer)
        self.assertIn("RestoreExistingInstall", installer)
        self.assertIn("StopInstalledProcesses", installer)
        self.assertIn("WaitForServiceRunning", installer)
        self.assertIn("WaitForServiceStable", installer)
        self.assertIn("existing enrollment and policy data", installer)
        repair = installer[installer.index("private static async Task RepairExistingAsync"):]
        repair = repair[:repair.index("private static async Task InstallNewAsync")]
        self.assertNotIn("/api/enroll", repair)
        self.assertNotIn("File.WriteAllText", repair)
        self.assertNotIn("EnsureRuleWorkerService", repair)

    def test_repair_installer_uses_protected_hash_and_signature_verified_staging(self):
        installer = self.read(
            "windows-agent/src/AppControlManager.Installer/Program.cs"
        )

        self.assertNotIn("Path.GetTempPath()", installer)
        self.assertIn("CreateSecureStagingDirectory", installer)
        self.assertIn('"InstallerStaging"', installer)
        self.assertIn("/inheritance:r", installer)
        self.assertIn("*S-1-5-18:(OI)(CI)(F)", installer)
        self.assertIn("*S-1-5-32-544:(OI)(CI)(F)", installer)
        self.assertIn("SHA256.HashData", installer)
        self.assertIn("requiredManifestPaths", installer)
        self.assertIn("Get-AuthenticodeSignature", installer)
        self.assertIn("ValidatePayload(payload,repair)", installer)

        repair = installer[installer.index("private static async Task RepairExistingAsync"):]
        repair = repair[:repair.index("private static async Task InstallNewAsync")]
        self.assertIn("ValidatePayload(payload,true)", repair)
        self.assertLess(
            repair.index("PreauthorizeRepairPayload"),
            repair.index("ValidatePayload(payload,true)"),
        )

    def test_repair_installer_preauthorizes_signed_payload_before_service_stop(self):
        installer = self.read(
            "windows-agent/src/AppControlManager.Installer/Program.cs"
        )
        repair = installer[installer.index("private static async Task RepairExistingAsync"):]
        repair = repair[:repair.index("private static async Task InstallNewAsync")]

        self.assertIn("PreauthorizeRepairPayload", repair)
        self.assertLess(
            repair.index("PreauthorizeRepairPayload"),
            repair.index("StopInstalledProcesses"),
        )
        self.assertIn('"New-SupplementalForFiles.ps1"', installer)
        self.assertIn('"Policies","BasePolicy.xml"', installer)
        self.assertIn("-FileListPath", installer)
        self.assertIn("-AlreadyExpanded", installer)
        self.assertIn("previous_preauth_policy_id", installer)

    def test_repair_does_not_stop_services_until_backup_is_complete(self):
        installer = self.read(
            "windows-agent/src/AppControlManager.Installer/Program.cs"
        )
        repair = installer[installer.index("private static async Task RepairExistingAsync"):]
        repair = repair[:repair.index("private static async Task InstallNewAsync")]

        self.assertLess(
            repair.index("BackupExistingInstall"),
            repair.index("StopInstalledProcesses"),
        )
        self.assertLess(repair.index("try"), repair.index("StopInstalledProcesses"))
        self.assertIn("RestoreExistingInstall(backup)", repair)

        backup = installer[installer.index("private static string BackupExistingInstall"):]
        backup = backup[:backup.index("private static string? PreauthorizeRepairPayload")]
        self.assertIn('"AppControlManager.Service.exe"', backup)
        self.assertIn('"AppControlManager.Tray.exe"', backup)
        self.assertIn("throw new InvalidOperationException", backup)

    def test_managed_activation_requires_complete_backup_before_service_stop(self):
        activation = self.read("windows-agent/scripts/Apply-AgentUpdate.ps1")
        tail = activation[activation.index("$stamp=Get-Date"):]

        self.assertIn("Prepare-RollbackBackup", activation)
        self.assertLess(
            tail.index("Prepare-RollbackBackup"),
            tail.index("Stop-Process -Name 'AppControlManager.Tray'"),
        )
        self.assertIn("backup preparation failed before services were stopped", tail)
        self.assertIn("Service\\AppControlManager.Service.exe", activation)
        self.assertIn("Tray\\AppControlManager.Tray.exe", activation)

    def test_successful_wdac_cleanup_retries_if_previous_policy_removal_fails(self):
        updater = self.read("windows-agent/src/AppGuard.Service/AgentUpdater.cs")
        success = updater[updater.index("// Successful update:"):]
        success = success[:success.index("// Failed/rolled-back update:")]

        catch = success[success.index("catch (Exception ex)"):success.index("WriteCurrent")]
        self.assertIn("return;", catch)

    def test_installer_persists_cleanup_record_atomically_before_service_stop(self):
        installer = self.read(
            "windows-agent/src/AppControlManager.Installer/Program.cs"
        )
        repair = installer[installer.index("private static async Task RepairExistingAsync"):]
        repair = repair[:repair.index("private static async Task InstallNewAsync")]
        self.assertLess(
            repair.index('WriteInstallerUpdateStatus("staged"'),
            repair.index("StopInstalledProcesses"),
        )

        writer = installer[installer.index("private static void WriteInstallerUpdateStatus"):]
        writer = writer[:writer.index("private static bool TryWriteInstallerUpdateStatus")]
        self.assertIn("File.Move", writer)
        self.assertIn("throw;", writer)


if __name__ == "__main__":
    unittest.main()
