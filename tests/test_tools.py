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


class FunctionalTest(unittest.TestCase):
    def run_tool(self, name, *args):
        path = os.path.join(BASE, "data", "scripts", name + ".py")
        r = subprocess.run([sys.executable, "-W", "ignore", path, *args],
                           capture_output=True, text=True, timeout=30, encoding="utf-8")
        return json.loads(r.stdout)

    def test_cidr_calculator(self):
        out = self.run_tool("cidr_subnet_calc", "192.168.1.0/24")
        self.assertEqual(out["usable_hosts"], 254)
        self.assertEqual(out["broadcast_address"], "192.168.1.255")

    def test_header_scanner_accepts_bare_host(self):
        out = self.run_tool("http_security_header_scanner", "localhost:1")
        self.assertTrue(out["error"].count("localhost"))  # tries http(s)://localhost:1, not a scheme error
        self.assertNotIn("No scheme", out["error"])


if __name__ == "__main__":
    unittest.main()
