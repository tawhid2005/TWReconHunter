import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TWReconHunterCLITests(unittest.TestCase):
    def test_cli_reports_and_writes_json_and_html(self):
        output_json = ROOT / 'out' / 'report.json'
        output_html = ROOT / 'out' / 'report.html'
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / 'twreconhunter.py'),
                '--target',
                'example.com',
                '--output-json',
                str(output_json),
                '--output-html',
                str(output_html),
                '--confirm-scope',
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue(output_json.exists())
        self.assertTrue(output_html.exists())
        data = json.loads(output_json.read_text(encoding='utf-8'))
        self.assertIn('target', data)
        self.assertIn('findings', data)
        self.assertIn('manual_review', data)


if __name__ == '__main__':
    unittest.main()
