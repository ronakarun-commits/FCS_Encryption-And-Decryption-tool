import os
import tempfile
from pathlib import Path

from crypto_utils import (
    AES_KEY_LENGTH,
    KDF_ITERATIONS,
    build_aad,
    decrypt_file,
    encrypt_file,
    parse_sfet_header,
)


def test_round_trip_and_randomized_ciphertext():
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "sample.txt"
        src.write_bytes(b"hello secret\nThis is a test file.\n")

        enc = Path(tmpdir) / "sample.txt.enc"
        ok = encrypt_file(str(src), str(enc), "StrongPass!123")
        assert ok["success"] is True
        assert enc.exists()

        dec = Path(tmpdir) / "sample_dec.txt"
        out = decrypt_file(str(enc), str(dec), "StrongPass!123")
        assert out["success"] is True
        assert dec.read_bytes() == src.read_bytes()

        second_enc = Path(tmpdir) / "sample2.txt.enc"
        encrypt_file(str(src), str(second_enc), "StrongPass!123")
        assert enc.read_bytes() != second_enc.read_bytes()


def test_wrong_password_and_tampering():
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "notes.bin"
        src.write_bytes(b"\x00\x01\x02\x03\x04\x05")

        enc = Path(tmpdir) / "notes.bin.enc"
        encrypt_file(str(src), str(enc), "CorrectPass!99")

        bad = decrypt_file(str(enc), str(Path(tmpdir) / "bad.out"), "WrongPass!99")
        assert bad["success"] is False
        assert "Authentication failed" in bad["message"] or "invalid" in bad["message"].lower()

        tampered = bytearray(enc.read_bytes())
        tampered[-1] ^= 0xFF
        tampered_path = Path(tmpdir) / "tampered.enc"
        tampered_path.write_bytes(tampered)

        fail = decrypt_file(str(tampered_path), str(Path(tmpdir) / "tampered.out"), "CorrectPass!99")
        assert fail["success"] is False
        assert "Authentication failed" in fail["message"]


def test_header_validation_and_aad_rejection():
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "header.txt"
        src.write_bytes(b"payload")

        enc = Path(tmpdir) / "header.txt.enc"
        encrypt_file(str(src), str(enc), "PassWord!1")

        invalid = Path(tmpdir) / "invalid.enc"
        invalid.write_bytes(b"NOTSFET")
        bad_header = decrypt_file(str(invalid), str(Path(tmpdir) / "invalid.out"), "PassWord!1")
        assert bad_header["success"] is False

        parsed = parse_sfet_header(enc.read_bytes())
        assert parsed["magic"] == b"SFET"
        assert parsed["version"] == 1
        assert parsed["kdf_id"] == 1
        assert parsed["iterations"] >= 600000
        assert len(parsed["salt"]) == 16
        assert len(parsed["nonce"]) == 12
        assert parsed["file_size"] == len(src.read_bytes())

        aad = build_aad(1, 1, b"header.txt", len(src.read_bytes()))
        assert isinstance(aad, bytes)
        assert len(aad) > 0

        tampered_header = bytearray(enc.read_bytes())
        tampered_header[40] ^= 0x01
        tampered_path = Path(tmpdir) / "tampered_header.enc"
        tampered_path.write_bytes(tampered_header)
        tampered = decrypt_file(str(tampered_path), str(Path(tmpdir) / "tampered_header.out"), "PassWord!1")
        assert tampered["success"] is False
        assert "Authentication failed" in tampered["message"]


def test_empty_file_round_trip():
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "empty.bin"
        src.write_bytes(b"")

        enc = Path(tmpdir) / "empty.bin.enc"
        assert encrypt_file(str(src), str(enc), "!Empty123")["success"] is True
        out = decrypt_file(str(enc), str(Path(tmpdir) / "empty.out"), "!Empty123")
        assert out["success"] is True
        assert Path(tmpdir, "empty.out").read_bytes() == b""


if __name__ == "__main__":
    test_round_trip_and_randomized_ciphertext()
    test_wrong_password_and_tampering()
    test_header_validation_and_aad_rejection()
    test_empty_file_round_trip()
    print("core crypto tests passed")
