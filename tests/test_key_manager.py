from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from app import load_private_key, load_public_key
from key_manager import generate_rsa_key_pair


class KeyManagerTests(unittest.TestCase):
    def test_generate_rsa_key_pair_creates_compatible_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)
            key_pair = generate_rsa_key_pair(output_dir=output_dir, key_name="cliente")

            self.assertTrue(key_pair.private_key_path.exists())
            self.assertTrue(key_pair.public_key_path.exists())
            self.assertEqual(key_pair.private_key_path.name, "cliente_private.pem")
            self.assertEqual(key_pair.public_key_path.name, "cliente_public.pem")

            loaded_public_key = load_public_key(key_pair.public_key_path)
            loaded_private_key = load_private_key(key_pair.private_key_path, password=None)

            self.assertEqual(loaded_public_key.key_size, 3072)
            self.assertEqual(loaded_private_key.key_size, 3072)

    def test_generate_rsa_key_pair_uses_incremental_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)

            first_pair = generate_rsa_key_pair(output_dir=output_dir, key_name="demo", key_size=2048)
            second_pair = generate_rsa_key_pair(output_dir=output_dir, key_name="demo", key_size=2048)

            self.assertEqual(first_pair.private_key_path.name, "demo_private.pem")
            self.assertEqual(second_pair.private_key_path.name, "demo_1_private.pem")
            self.assertNotEqual(first_pair.private_key_path, second_pair.private_key_path)
            self.assertTrue(second_pair.public_key_path.exists())

    def test_generate_rsa_key_pair_can_encrypt_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)
            key_pair = generate_rsa_key_pair(
                output_dir=output_dir,
                key_name="seguro",
                key_size=2048,
                password="clave123",
            )

            loaded_private_key = load_private_key(key_pair.private_key_path, password="clave123")
            self.assertEqual(loaded_private_key.key_size, 2048)

            if stat.S_ISREG(key_pair.private_key_path.stat().st_mode):
                owner_mode = stat.S_IMODE(key_pair.private_key_path.stat().st_mode)
                self.assertEqual(owner_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
