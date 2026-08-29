import inspect, sys, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'server'))
import app


class ReleaseCandidateAuthorizationMatrixTests(unittest.TestCase):
    def test_every_admin_mutation_requires_browser_authentication(self):
        missing=[]
        for route in app.app.routes:
            methods=set(getattr(route,'methods',set()) or set())
            if not route.path.startswith('/admin/') or not methods.intersection({'POST','PUT','PATCH','DELETE'}):
                continue
            dependency_names={getattr(dep.call,'__name__','') for dep in route.dependant.dependencies}
            signature=inspect.signature(route.endpoint)
            if 'admin_auth' not in dependency_names and not any(
                getattr(param.default,'dependency',None) is app.admin_auth for param in signature.parameters.values()
            ):
                missing.append(f"{','.join(sorted(methods))} {route.path}")
        self.assertEqual(missing,[])

    def test_agent_mutations_require_device_authentication(self):
        missing=[]
        for route in app.app.routes:
            methods=set(getattr(route,'methods',set()) or set())
            if not route.path.startswith('/api/') or not methods.intersection({'POST','PUT','PATCH','DELETE'}): continue
            if route.path in {'/api/enroll'}: continue
            dependencies={getattr(dep.call,'__name__','') for dep in route.dependant.dependencies}
            if 'agent_auth' not in dependencies: missing.append(route.path)
        self.assertEqual(missing,[])


if __name__=='__main__': unittest.main()
