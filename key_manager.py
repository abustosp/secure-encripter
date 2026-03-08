from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_KEYS_DIR = BASE_DIR / "keys"
DEFAULT_KEY_NAME = "secure_encrypter"
VALID_KEY_SIZES = (2048, 3072, 4096)


@dataclass(frozen=True)
class GeneratedKeyPair:
    private_key_path: Path
    public_key_path: Path


def build_key_paths(output_dir: Path, key_name: str, overwrite: bool = False) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    clean_name = key_name.strip()
    if not clean_name:
        raise ValueError("El nombre base de la llave no puede estar vacío.")

    if overwrite:
        return (
            output_dir / f"{clean_name}_private.pem",
            output_dir / f"{clean_name}_public.pem",
        )

    counter = 0
    while True:
        suffix = "" if counter == 0 else f"_{counter}"
        private_key_path = output_dir / f"{clean_name}{suffix}_private.pem"
        public_key_path = output_dir / f"{clean_name}{suffix}_public.pem"
        if not private_key_path.exists() and not public_key_path.exists():
            return private_key_path, public_key_path
        counter += 1


def generate_rsa_key_pair(
    output_dir: Path | None = None,
    key_name: str = DEFAULT_KEY_NAME,
    key_size: int = 3072,
    password: str | None = None,
    overwrite: bool = False,
) -> GeneratedKeyPair:
    if key_size not in VALID_KEY_SIZES:
        raise ValueError(
            f"Tamaño de llave no soportado: {key_size}. Usa uno de {VALID_KEY_SIZES}."
        )

    target_dir = output_dir or DEFAULT_KEYS_DIR
    private_key_path, public_key_path = build_key_paths(
        output_dir=target_dir,
        key_name=key_name,
        overwrite=overwrite,
    )

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_key_path.write_bytes(private_key_bytes)
    public_key_path.write_bytes(public_key_bytes)

    if os.name != "nt":
        os.chmod(private_key_path, 0o600)

    return GeneratedKeyPair(
        private_key_path=private_key_path,
        public_key_path=public_key_path,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Genera un par de llaves RSA compatibles con Secure Encrypter.",
    )
    parser.add_argument(
        "--name",
        default=DEFAULT_KEY_NAME,
        help="Nombre base de los archivos de llave.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_KEYS_DIR,
        help="Directorio donde se guardarán las llaves.",
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=3072,
        choices=VALID_KEY_SIZES,
        help="Tamaño de la llave RSA.",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Password opcional para cifrar la private key.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Sobrescribe los archivos si ya existen.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    key_pair = generate_rsa_key_pair(
        output_dir=args.output_dir,
        key_name=args.name,
        key_size=args.key_size,
        password=args.password,
        overwrite=args.overwrite,
    )
    print(f"Private key: {key_pair.private_key_path}")
    print(f"Public key: {key_pair.public_key_path}")


if __name__ == "__main__":
    main()
