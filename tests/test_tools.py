import json
import os
import subprocess
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(BASE, "data", "tools.json"), encoding="utf-8") as f:
    TOOLS = json.load(f)["tools"]


class ToolsTest(unittest.TestCase):
    def test_unique_ids(self):
        ids = [t["id"] for t in TOOLS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_files_exist(self):
        for t in TOOLS:
            with self.subTest(tool=t["id"]):
                self.assertTrue(os.path.isfile(os.path.join(BASE, t["file_path"])))
                self.assertTrue(os.path.isfile(os.path.join(BASE, t["review_path"])))

    def test_syntax(self):
        for t in TOOLS:
            with self.subTest(tool=t["id"]):
                with open(os.path.join(BASE, t["file_path"]), encoding="utf-8-sig") as fh:
                    compile(fh.read(), t["file_path"], "exec")

    def test_help_runs(self):
        for t in TOOLS:
            with self.subTest(tool=t["id"]):
                path = os.path.join(BASE, t["file_path"])
                r = subprocess.run(
                    [sys.executable, path, "--help"],
                    capture_output=True, text=True, timeout=30,
                    cwd=os.path.dirname(path), encoding="utf-8", errors="replace",
                )
                if "ModuleNotFoundError" in r.stderr:
                    self.skipTest("missing dependency: " + r.stderr.strip().splitlines()[-1])
                self.assertNotIn("Traceback", r.stderr, r.stderr[-400:])


if __name__ == "__main__":
    unittest.main()
