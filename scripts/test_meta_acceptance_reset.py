import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('reset', Path(__file__).with_name('meta-acceptance-reset.py'))
reset = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reset)


class ScopeTests(unittest.TestCase):
    def test_rejects_broad_root_before_actions(self):
        for root in ('/', '/home/test', '/home/test/ordinary-box', '/tmp/facets-meta-acceptance-20260912'):
            with self.assertRaises(ValueError):
                reset.validated_paths(root, root, root, root, 'facets-meta-acceptance-20260912-new', 'facets-meta-acceptance-20260912')

    def test_rejects_same_project(self):
        with self.assertRaises(ValueError):
            reset.validated_paths('/home/test/facets-meta-acceptance-20260912', '/', '/', '/',
                                  'facets-meta-acceptance-20260912', 'facets-meta-acceptance-20260912')

    def test_workflow_never_deletes_or_migrates_old_volumes(self):
        source = Path(reset.__file__).read_text()
        self.assertNotIn("['down'", source)
        self.assertNotIn("'volume', 'rm'", source)
        self.assertLess(source.index("['build', 'server'"), source.index("['stop', 'controller'"))
        self.assertLess(source.index("['stop'])"), source.index("['up', '-d'"))
