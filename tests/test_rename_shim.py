import subprocess
import sys
import unittest


class TestOldNameShim(unittest.TestCase):
    def test_old_import_warns_and_reexports(self):
        code = ("import warnings\n"
                "with warnings.catch_warnings(record=True) as w:\n"
                "    warnings.simplefilter('always')\n"
                "    import mcp_audit, mcp_gradecard\n"
                "assert mcp_audit.__version__ == mcp_gradecard.__version__\n"
                "print([x.category.__name__ for x in w])")
        p = subprocess.run([sys.executable, "-c", code],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("DeprecationWarning", p.stdout)

    def test_old_module_entry_still_runs(self):
        p = subprocess.run([sys.executable, "-m", "mcp_audit", "--version"],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("mcp-gradecard", p.stdout)


if __name__ == "__main__":
    unittest.main()
