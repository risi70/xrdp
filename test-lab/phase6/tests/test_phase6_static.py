import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

SKIP_DIRS = {'.git', '__pycache__', 'artifacts', 'images', 'isos', 'reports'}


def iter_lab_files():
    for path in ROOT.rglob('*'):
        if path.is_file() and not (set(path.parts) & SKIP_DIRS):
            yield path

class Phase6StaticTests(unittest.TestCase):
    def test_required_kvm_artifacts_exist(self):
        required = [
            'kvm/libvirt/networks/xrdp-baf-lab.xml',
            'kvm/cloud-init/openuds/user-data',
            'kvm/cloud-init/ubuntu-vdi/user-data',
            'kvm/ansible/playbooks/site.yml',
            'kvm/scripts/run-phase6-tests.sh',
            'kvm/scripts/run-xfreerdp-test.sh',
            'kvm/scripts/check-prereqs.sh',
            'kvm/scripts/check-image.sh',
            'kvm/scripts/download-ubuntu-image.sh',
            'kvm/scripts/create-lab.sh',
            'kvm/scripts/sync-source.sh',
        ]
        for rel in required:
            self.assertTrue((ROOT / rel).exists(), rel)

    def test_no_docker_variant(self):
        for path in iter_lab_files():
            if path == pathlib.Path(__file__).resolve():
                continue
            text = path.read_text(errors='ignore')
            self.assertNotRegex(text, r'docker\s+(run|compose)|docker' + '-compose')

    def test_no_credential_field_overload(self):
        texts = []
        for item in iter_lab_files():
            if item != pathlib.Path(__file__).resolve():
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


    def test_runner_modes_are_documented(self):
        script = (ROOT / 'kvm/scripts/run-phase6-tests.sh').read_text()
        self.assertIn('--static-only', script)
        self.assertIn('--require-vms', script)
        self.assertIn('failed_required_vm_check', script)

    def test_xfreerdp_rdsaad_skip_is_explicit(self):
        script = (ROOT / 'kvm/scripts/run-xfreerdp-test.sh').read_text()
        self.assertIn('stock xfreerdp', script)
        self.assertIn('exit 77', script)

if __name__ == '__main__':
    unittest.main()
