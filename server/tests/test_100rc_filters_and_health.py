import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'server'))
import app


class ReleaseCandidateFilterAndHealthTests(unittest.TestCase):
    def test_operational_filters_are_bounded_and_normalized(self):
        principal=app.Principal(1,'admin','Admin','org_admin',42)
        result=app.parse_operational_filters({'q':'  Chrome  ','status':'FAILED','organization_id':'42','page':'3'},principal)
        self.assertEqual(result.query,'Chrome'); self.assertEqual(result.status,'failed')
        self.assertEqual(result.organization_id,42); self.assertEqual(result.page,3)
        with self.assertRaises(ValueError): app.parse_operational_filters({'q':'x'*257},principal)
        with self.assertRaises(PermissionError): app.parse_operational_filters({'organization_id':'99'},principal)

    def test_health_distinguishes_working_attention_failed_and_offline(self):
        now=datetime.now(timezone.utc)
        base={'last_seen':now.isoformat(),'service_status':'running','rule_worker_status':'running','background_policy_status':'idle','background_policy_failed':0,'update_status':None}
        self.assertEqual(app.classify_device_health(base,now)[0],'Healthy')
        self.assertEqual(app.classify_device_health({**base,'background_policy_status':'processing'},now)[0],'Working')
        self.assertEqual(app.classify_device_health({**base,'rule_worker_status':'stopped'},now)[0],'Attention')
        self.assertEqual(app.classify_device_health({**base,'background_policy_failed':1},now)[0],'Failed')
        self.assertEqual(app.classify_device_health({**base,'last_seen':(now-timedelta(minutes=20)).isoformat()},now)[0],'Offline')


if __name__=='__main__': unittest.main()
