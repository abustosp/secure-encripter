from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import decrypt_package, encrypt_zip, load_private_key, load_public_key, zip_folder


class SecureEncrypterTests(unittest.TestCase):
    def test_encrypt_and_decrypt_folder_with_pem_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            source_dir = base / "prueba"
            nested_dir = source_dir / "subcarpeta"
            nested_dir.mkdir(parents=True)
            (source_dir / "archivo.txt").write_text("hola", encoding="utf-8")
            (nested_dir / "datos.csv").write_text("a,b\n1,2\n", encoding="utf-8")

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            private_key_path = base / "private.pem"
            public_key_path = base / "public.pem"
            private_key_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            public_key_path.write_bytes(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

            zip_path = base / "prueba.zip"
            zip_folder(source_dir, zip_path)
            encrypted_path = base / "prueba.securezip"
            encrypt_zip(zip_path, public_key_path, encrypted_path, "folder")

            output_dir = base / "salida"
            restored_zip, extracted_dir = decrypt_package(
                encrypted_path=encrypted_path,
                private_key_path=private_key_path,
                password=None,
                output_dir=output_dir,
                extract_zip=True,
            )

            self.assertTrue(restored_zip.exists())
            self.assertIsNotNone(extracted_dir)
            self.assertEqual(
                (extracted_dir / "prueba" / "archivo.txt").read_text(encoding="utf-8"),
                "hola",
            )
            self.assertEqual(
                (extracted_dir / "prueba" / "subcarpeta" / "datos.csv").read_text(encoding="utf-8"),
                "a,b\n1,2\n",
            )

            with zipfile.ZipFile(restored_zip, "r") as archive:
                names = sorted(archive.namelist())
            self.assertEqual(names, ["prueba/archivo.txt", "prueba/subcarpeta/datos.csv"])

    def test_load_openssh_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            private_key_path = base / "id_rsa"
            public_key_path = base / "id_rsa.pub"

            private_key_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.OpenSSH,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            public_key_path.write_bytes(
                public_key.public_bytes(
                    encoding=serialization.Encoding.OpenSSH,
                    format=serialization.PublicFormat.OpenSSH,
                )
            )

            loaded_public_key = load_public_key(public_key_path)
            loaded_private_key = load_private_key(private_key_path, password=None)

            self.assertIsInstance(loaded_public_key, rsa.RSAPublicKey)
            self.assertIsInstance(loaded_private_key, rsa.RSAPrivateKey)


if __name__ == "__main__":
    unittest.main()
