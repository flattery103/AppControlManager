import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ServiceCrashRecoveryConfigurationTests(unittest.TestCase):
    def read(self, relative_path):
        return (ROOT / relative_path).read_text(encoding="utf-8")

    def assert_recovery_contract(self, text, service_name):
        self.assertIn(service_name, text)
        self.assertIn("reset=", text)
        self.assertIn("86400", text)
        self.assertIn("restart/10000/restart/30000/restart/60000", text)
        self.assertIn("failureflag", text)

    def test_running_agent_repairs_recovery_for_main_and_worker_services(self):
        provisioner = self.read(
            "windows-agent/src/AppGuard.Service/RuleWorkerProvisioner.cs"
        )
        self.assert_recovery_contract(provisioner, "AppControlManager")
        self.assert_recovery_contract(provisioner, "AppControlManagerRuleWorker")
        self.assertIn("ConfigureCrashRecovery(ServiceName)", provisioner)
        self.assertIn('ConfigureCrashRecovery("AppControlManager")', provisioner)

    def test_gui_installer_configures_main_service_recovery_before_start(self):
        installer = self.read(
            "windows-agent/src/AppControlManager.Installer/Program.cs"
        )
        self.assert_recovery_contract(installer, "AppControlManager")
        self.assertIn("ConfigureServiceCrashRecovery", installer)
        ensure = installer[
            installer.index("private static void EnsureMainService()") :
        ]
        self.assertLess(
            ensure.index("ConfigureServiceCrashRecovery"),
            ensure.index("private static void RegisterTrayStartup"),
        )

    def test_manual_install_and_upgrade_configure_main_service_recovery(self):
        for relative_path in (
            "windows-agent/Install-Agent.ps1",
            "windows-agent/Upgrade-Agent.ps1",
        ):
            with self.subTest(relative_path=relative_path):
                script = self.read(relative_path)
                self.assert_recovery_contract(script, "AppControlManager")
                self.assertIn("Set-ServiceCrashRecovery", script)


if __name__ == "__main__":
    unittest.main()
