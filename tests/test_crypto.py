import tempfile
import unittest
from pathlib import Path

from crypto_utils import (
    build_aad,
    decrypt_file,
    encrypt_file,
    parse_sfet_header,
)


class CryptoCoreTests(unittest.TestCase):
    def test_round_trip_and_randomized_ciphertext(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "sample.txt"
            src.write_bytes(b"hello secret\nThis is a test file.\n")

            enc = Path(tmpdir) / "sample.txt.enc"
            ok = encrypt_file(str(src), str(enc), "StrongPass!123")
            self.assertTrue(ok["success"], ok.get("message"))
            self.assertTrue(enc.exists())

            dec = Path(tmpdir) / "sample_dec.txt"
            out = decrypt_file(str(enc), str(dec), "StrongPass!123")
            self.assertTrue(out["success"], out.get("message"))
            self.assertEqual(dec.read_bytes(), src.read_bytes())

            second_enc = Path(tmpdir) / "sample2.txt.enc"
            encrypt_file(str(src), str(second_enc), "StrongPass!123")
            self.assertNotEqual(enc.read_bytes(), second_enc.read_bytes())

    def test_wrong_password_and_tampering(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "notes.bin"
            src.write_bytes(b"\x00\x01\x02\x03\x04\x05")

            enc = Path(tmpdir) / "notes.bin.enc"
            encrypt_file(str(src), str(enc), "CorrectPass!99")

            bad = decrypt_file(str(enc), str(Path(tmpdir) / "bad.out"), "WrongPass!99")
            self.assertFalse(bad["success"])
            self.assertIn("Authentication failed", bad["message"])

            tampered = bytearray(enc.read_bytes())
            tampered[-1] ^= 0xFF
            tampered_path = Path(tmpdir) / "tampered.enc"
            tampered_path.write_bytes(tampered)

            fail = decrypt_file(str(tampered_path), str(Path(tmpdir) / "tampered.out"), "CorrectPass!99")
            self.assertFalse(fail["success"])
            self.assertIn("Authentication failed", fail["message"])

    def test_header_validation_and_aad_rejection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "header.txt"
            src.write_bytes(b"payload")

            enc = Path(tmpdir) / "header.txt.enc"
            encrypt_file(str(src), str(enc), "PassWord!1")

            invalid = Path(tmpdir) / "invalid.enc"
            invalid.write_bytes(b"NOTSFET")
            bad_header = decrypt_file(str(invalid), str(Path(tmpdir) / "invalid.out"), "PassWord!1")
            self.assertFalse(bad_header["success"])

            parsed = parse_sfet_header(enc.read_bytes())
            self.assertEqual(parsed["magic"], b"SFET")
            self.assertEqual(parsed["version"], 1)
            self.assertEqual(parsed["kdf_id"], 1)
            self.assertGreaterEqual(parsed["iterations"], 600000)
            self.assertEqual(len(parsed["salt"]), 16)
            self.assertEqual(len(parsed["nonce"]), 12)
            self.assertEqual(parsed["file_size"], len(src.read_bytes()))

            aad = build_aad(1, 1, b"header.txt", len(src.read_bytes()))
            self.assertIsInstance(aad, bytes)
            self.assertGreater(len(aad), 0)

            tampered_header = bytearray(enc.read_bytes())
            tampered_header[40] ^= 0x01
            tampered_path = Path(tmpdir) / "tampered_header.enc"
            tampered_path.write_bytes(tampered_header)
            tampered = decrypt_file(str(tampered_path), str(Path(tmpdir) / "tampered_header.out"), "PassWord!1")
            self.assertFalse(tampered["success"])
            self.assertIn("Authentication failed", tampered["message"])

    def test_empty_file_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "empty.bin"
            src.write_bytes(b"")

            enc = Path(tmpdir) / "empty.bin.enc"
            self.assertTrue(encrypt_file(str(src), str(enc), "!Empty123")["success"])
            out = decrypt_file(str(enc), str(Path(tmpdir) / "empty.out"), "!Empty123")
            self.assertTrue(out["success"], out.get("message"))
            self.assertEqual(Path(tmpdir, "empty.out").read_bytes(), b"")

    def test_output_file_conflict_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "sample.bin"
            src.write_bytes(b"abc")

            output = Path(tmpdir) / "sample.bin.enc"
            output.write_bytes(b"existing-content")

            result = encrypt_file(str(src), str(output), "Pass!123")
            self.assertFalse(result["success"])
            self.assertIn("Output file already exists", result["message"])

            enc = Path(tmpdir) / "encrypted.enc"
            encrypt_file(str(src), str(enc), "Pass!123")

            decrypted_target = Path(tmpdir) / "already_here.txt"
            decrypted_target.write_bytes(b"old data")
            result2 = decrypt_file(str(enc), str(decrypted_target), "Pass!123")
            self.assertFalse(result2["success"])
            self.assertIn("Output file already exists", result2["message"])


if __name__ == "__main__":
    unittest.main()
