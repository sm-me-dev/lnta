import hashlib
import pathlib
import tempfile
import unittest

import verify_repository


class VerifyRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        (self.root / "dists/stable").mkdir(parents=True)
        (self.root / "dists/stable/InRelease").write_text("signature fixture")

    def tearDown(self):
        self.temp.cleanup()

    def add_package(self, arch, data=b"deb fixture"):
        relative = pathlib.Path("pool/main/l/lnta") / f"lnta_{arch}.deb"
        artifact = self.root / relative
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(data)
        index = self.root / "dists/stable/main" / f"binary-{arch}/Packages"
        index.parent.mkdir(parents=True, exist_ok=True)
        index.write_text(
            "Package: lnta\n"
            "Version: 1.2.3\n"
            f"Architecture: {arch}\n"
            f"Filename: {relative.as_posix()}\n"
            f"Size: {len(data)}\n"
            f"SHA256: {hashlib.sha256(data).hexdigest()}\n"
        )

    def complete(self):
        self.add_package("amd64")
        self.add_package("arm64")

    def test_accepts_both_expected_architectures_and_checksums(self):
        self.complete()
        verify_repository.verify(self.root, "1.2.3")

    def test_rejects_missing_architecture(self):
        self.add_package("amd64")
        with self.assertRaisesRegex(ValueError, "arm64"):
            verify_repository.verify(self.root, "1.2.3")

    def test_rejects_checksum_mismatch(self):
        self.complete()
        artifact = next((self.root / "pool").rglob("lnta_amd64.deb"))
        artifact.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            verify_repository.verify(self.root, "1.2.3")

    def test_rejects_missing_signature_metadata(self):
        self.complete()
        (self.root / "dists/stable/InRelease").unlink()
        with self.assertRaisesRegex(ValueError, "InRelease"):
            verify_repository.verify(self.root, "1.2.3")


if __name__ == "__main__":
    unittest.main()
