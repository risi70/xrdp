import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

class Phase6StaticTests(unittest.TestCase):
    def test_required_kvm_artifacts_exist(self):
        required = [
            'kvm/libvirt/networks/xrdp-baf-lab.xml',
            'kvm/cloud-init/openuds/user-data',
            'kvm/cloud-init/ubuntu-vdi/user-data',
            'kvm/ansible/playbooks/site.yml',
            'kvm/scripts/run-phase6-tests.sh',
            'kvm/scripts/run-xfreerdp-test.sh',
        ]
        for rel in required:
            self.assertTrue((ROOT / rel).exists(), rel)

    def test_no_docker_variant(self):
        for path in ROOT.rglob('*'):
            if path.is_file() and '.git' not in path.parts and '__pycache__' not in path.parts:
                if path == pathlib.Path(__file__).resolve():
                    continue
                text = path.read_text(errors='ignore')
                self.assertNotRegex(text, r'docker\s+(run|compose)|docker' + '-compose')

    def test_no_credential_field_overload(self):
        texts = []
        for item in ROOT.rglob('*'):
            if item.is_file() and '__pycache__' not in item.parts and item != pathlib.Path(__file__).resolve():
                texts.append(item.read_text(errors='ignore'))
        combined = '\n'.join(texts)
        left = 'pass' + 'word'
        right = 'asser' + 'tion'
        pattern = re.compile(left + '.*' + right + '|' + right + '.*' + left, re.I)
        self.assertNotRegex(combined, pattern)

    def test_images_are_ignored(self):
        ignore = (ROOT / '.gitignore').read_text()
        for pattern in ['*.iso', '*.img', '*.qcow2', '*.raw']:
            self.assertIn(pattern, ignore)

    def test_xfreerdp_rdsaad_skip_is_explicit(self):
        script = (ROOT / 'kvm/scripts/run-xfreerdp-test.sh').read_text()
        self.assertIn('stock xfreerdp', script)
        self.assertIn('exit 77', script)

if __name__ == '__main__':
    unittest.main()
