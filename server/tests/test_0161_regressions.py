import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SERVER_DIR = ROOT / 'server'
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))
os.environ.setdefault('APPCONTROL_DB', str(Path(tempfile.gettempdir()) / 'acm-test-0161.db'))


class Release0161RegressionTests(unittest.TestCase):
    def test_learning_to_enforcement_uses_learned_paths_without_bundle_reexpansion(self):
        text = (ROOT / 'windows-agent' / 'scripts' / 'End-LearningAndEnforce.ps1').read_text(encoding='utf-8')
        self.assertIn('Select-Object -Unique', text)
        self.assertIn('ACM_STAGE learned-collection', text)
        self.assertIn('ACM_STAGE learned-dedup', text)
        self.assertIn('ACM_STAGE enforcement-total', text)
        self.assertIn("StartsWith('ACM_STAGE')", text)
        # 0.16.1 removed recursive bundle re-expansion. Later releases may route the learned
        # snapshot through a dedicated baseline builder, but must not restore the old
        # New-SupplementalForFiles call without -AlreadyExpanded.
        if 'New-SupplementalForFiles.ps1' in text:
            self.assertIn('-AlreadyExpanded', text)

    def test_supplemental_helper_emits_policy_stage_timings(self):
        text = (ROOT / 'windows-agent' / 'scripts' / 'New-SupplementalForFiles.ps1').read_text(encoding='utf-8')
        for marker in (
            'ACM_STAGE rule-generation',
            'ACM_STAGE policy-xml',
            'ACM_STAGE policy-convert',
            'ACM_STAGE policy-install',
        ):
            self.assertIn(marker, text)

    def test_agent_runs_maintenance_and_commands_in_independent_loops(self):
        text = (ROOT / 'windows-agent' / 'src' / 'AppGuard.Service' / 'AgentWorker.cs').read_text(encoding='utf-8')
        self.assertIn('RunMaintenanceLoopAsync', text)
        self.assertIn('RunCommandLoopAsync', text)
        self.assertIn('Task.WhenAll(maintenanceTask, commandTask, pipeTask)', text)
        maintenance = text[text.index('private async Task RunMaintenanceLoopAsync'):text.index('private async Task RunCommandLoopAsync')]
        self.assertIn('HeartbeatAsync', maintenance)
        self.assertNotIn('ProcessCommandsAsync', maintenance)

    def test_policy_helper_filters_configci_scan_success_noise_and_logs_stage_markers(self):
        text = (ROOT / 'windows-agent' / 'src' / 'AppGuard.Service' / 'PolicyHelper.cs').read_text(encoding='utf-8')
        self.assertIn('IsPolicyHelperNoise', text)
        self.assertIn('Scan completed successfully', text)
        self.assertIn('ACM_STAGE', text)
        self.assertIn('enforcement-progress', text)

    def test_server_update_systemd_handoff_is_nonblocking(self):
        import app as app_module
        app_module.SERVER_UPDATE_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
        app_module.SERVER_UPDATE_SCRIPT.touch(exist_ok=True)
        fake = type('Result', (), {'returncode': 0, 'stdout': 'Running as unit', 'stderr': ''})()
        with patch.object(app_module, '_server_update_unit_active', return_value=False), \
             patch.object(app_module.subprocess, 'run', return_value=fake) as run:
            app_module._launch_server_update()
        argv = run.call_args.args[0]
        self.assertIn('--no-block', argv)
        self.assertIn('--collect', argv)


if __name__ == '__main__':
    unittest.main()
