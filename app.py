from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from key_manager import generate_rsa_key_pair


APP_TITLE = "Secure Encrypter"
PACKAGE_MAGIC = b"SEZ1"
PACKAGE_VERSION = 1
NONCE_SIZE = 12
BG = "#2e2e2e"
FG = "#ffffff"
ACCENT = "#d35400"
STATUS_BG = "#1b1b1b"


class CryptoError(Exception):
    pass


def ensure_unique_path(path: Path) -> Path:
    if not path.exists():
        return path

    candidate = path
    counter = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.stem}_{counter}{path.suffix}")
        counter += 1
    return candidate


def resource_path(*relative_parts: str) -> Path:
    candidates: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass))
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent)
    candidates.append(Path(__file__).resolve().parent)

    for base_path in candidates:
        candidate = base_path.joinpath(*relative_parts)
        if candidate.exists():
            return candidate

    return candidates[0].joinpath(*relative_parts)


def zip_folder(source_dir: Path, zip_path: Path) -> None:
    root_name = source_dir.name
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in source_dir.rglob("*"):
            if item.is_file():
                arcname = Path(root_name) / item.relative_to(source_dir)
                archive.write(item, arcname=str(arcname))


def zip_file(source_file: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(source_file, arcname=source_file.name)


def load_public_key(public_key_path: Path) -> rsa.RSAPublicKey:
    key_data = public_key_path.read_bytes()
    try:
        public_key = serialization.load_pem_public_key(key_data)
    except ValueError:
        try:
            public_key = serialization.load_ssh_public_key(key_data)
        except (TypeError, ValueError) as exc:
            raise CryptoError(
                "No se pudo leer la public key. Usa una clave RSA en formato PEM u OpenSSH."
            ) from exc

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CryptoError("La public key debe ser RSA en formato PEM u OpenSSH. Claves ED25519 o ECDSA no sirven para cifrar aquí.")
    return public_key


def load_private_key(private_key_path: Path, password: str | None) -> rsa.RSAPrivateKey:
    key_data = private_key_path.read_bytes()
    password_bytes = password.encode("utf-8") if password else None
    try:
        private_key = serialization.load_pem_private_key(
            key_data,
            password=password_bytes,
        )
    except ValueError:
        try:
            private_key = serialization.load_ssh_private_key(
                key_data,
                password=password_bytes,
            )
        except (TypeError, ValueError) as exc:
            raise CryptoError(
                "No se pudo leer la private key. Usa una clave RSA en formato PEM u OpenSSH y revisa el password."
            ) from exc
    except TypeError as exc:
        raise CryptoError("La private key requiere un password válido.") from exc

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptoError("La private key debe ser RSA en formato PEM u OpenSSH. Claves ED25519 o ECDSA no sirven para descifrar aquí.")
    return private_key


def encrypt_zip(zip_path: Path, public_key_path: Path, output_path: Path, source_kind: str) -> Path:
    public_key = load_public_key(public_key_path)
    zip_bytes = zip_path.read_bytes()

    metadata = {
        "archive_name": zip_path.name,
        "source_kind": source_kind,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    metadata_bytes = json.dumps(metadata, ensure_ascii=True).encode("utf-8")

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_SIZE)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    ciphertext = AESGCM(aes_key).encrypt(nonce, zip_bytes, metadata_bytes)

    package = b"".join(
        [
            PACKAGE_MAGIC,
            struct.pack(">BII", PACKAGE_VERSION, len(metadata_bytes), len(encrypted_key)),
            metadata_bytes,
            encrypted_key,
            nonce,
            ciphertext,
        ]
    )

    output_path.write_bytes(package)
    return output_path


def decrypt_package(
    encrypted_path: Path,
    private_key_path: Path,
    password: str | None,
    output_dir: Path,
    extract_zip: bool,
) -> tuple[Path, Path | None]:
    private_key = load_private_key(private_key_path, password)
    payload = encrypted_path.read_bytes()

    if len(payload) < 13 or payload[:4] != PACKAGE_MAGIC:
        raise CryptoError("El archivo no tiene un formato válido de Secure Encrypter.")

    version, metadata_length, encrypted_key_length = struct.unpack(">BII", payload[4:13])
    if version != PACKAGE_VERSION:
        raise CryptoError(f"Versión de paquete no soportada: {version}.")

    cursor = 13
    metadata_bytes = payload[cursor:cursor + metadata_length]
    cursor += metadata_length

    encrypted_key = payload[cursor:cursor + encrypted_key_length]
    cursor += encrypted_key_length

    nonce = payload[cursor:cursor + NONCE_SIZE]
    cursor += NONCE_SIZE
    ciphertext = payload[cursor:]

    if len(nonce) != NONCE_SIZE or not ciphertext:
        raise CryptoError("El paquete está incompleto o corrupto.")

    metadata = json.loads(metadata_bytes.decode("utf-8"))
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    zip_bytes = AESGCM(aes_key).decrypt(nonce, ciphertext, metadata_bytes)

    output_dir.mkdir(parents=True, exist_ok=True)
    zip_name = metadata.get("archive_name", f"{encrypted_path.stem}.zip")
    zip_path = ensure_unique_path(output_dir / zip_name)
    zip_path.write_bytes(zip_bytes)

    extracted_to = None
    if extract_zip:
        extract_dir = ensure_unique_path(output_dir / zip_path.stem)
        extract_dir.mkdir(parents=True, exist_ok=False)
        with zipfile.ZipFile(zip_path, "r") as archive:
            archive.extractall(extract_dir)
        extracted_to = extract_dir

    return zip_path, extracted_to


class SecureEncrypterApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1120x760")
        self.root.minsize(1020, 720)
        self.root.configure(background=BG)
        self.icon_image = None
        self.logo_image = None

        self.status_var = tk.StringVar(value="Listo para comprimir, cifrar o descifrar.")
        self.encrypt_source_mode = tk.StringVar(value="folder")
        self.encrypt_source_path = tk.StringVar()
        self.encrypt_public_key_path = tk.StringVar()
        self.encrypt_output_dir = tk.StringVar(value=str(Path.cwd()))
        self.encrypt_output_name = tk.StringVar()

        self.decrypt_input_path = tk.StringVar()
        self.decrypt_private_key_path = tk.StringVar()
        self.decrypt_private_password = tk.StringVar()
        self.decrypt_output_dir = tk.StringVar(value=str(Path.cwd()))
        self.extract_after_decrypt = tk.BooleanVar(value=True)
        self.keys_output_dir = tk.StringVar(value=str(Path.cwd() / "keys"))
        self.keys_name = tk.StringVar(value="secure_encrypter")
        self.keys_size = tk.StringVar(value="3072")
        self.keys_password = tk.StringVar()

        self.action_buttons: list[ttk.Button] = []
        self.menu_buttons: dict[str, ttk.Button] = {}
        self.panels: dict[str, ttk.Frame] = {}
        self.progress = None

        self.configure_styles()
        self.apply_window_branding()
        self.build_ui()

    def apply_window_branding(self) -> None:
        icon_ico_path = resource_path("bin", "ABP-blanco-en-fondo-negro.ico")
        icon_png_path = resource_path("bin", "ABP blanco sin fondo.png")
        logo_path = resource_path("bin", "MrBot.png")

        try:
            if icon_ico_path.exists():
                self.root.iconbitmap(str(icon_ico_path))
        except Exception:
            pass

        try:
            if icon_png_path.exists():
                self.icon_image = tk.PhotoImage(file=str(icon_png_path))
                self.root.iconphoto(True, self.icon_image)
        except Exception:
            self.icon_image = None

        try:
            if logo_path.exists():
                self.logo_image = tk.PhotoImage(file=str(logo_path))
        except Exception:
            self.logo_image = None

    def configure_styles(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", font=("Arial", 10))
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("TButton", foreground="#000000", padding=(10, 6))
        style.map("TButton", background=[("active", "#e6e6e6")])
        style.configure("Menu.TButton", font=("Arial", 10, "bold"), padding=(16, 10))
        style.configure(
            "SelectedMenu.TButton",
            font=("Arial", 10, "bold"),
            padding=(16, 10),
            background=ACCENT,
            foreground=FG,
        )
        style.map(
            "SelectedMenu.TButton",
            background=[("active", "#b64900"), ("disabled", "#7c7c7c")],
            foreground=[("disabled", "#eaeaea")],
        )
        style.configure("Title.TLabel", background=BG, foreground=FG, font=("Arial", 16, "bold"))
        style.configure("Subtitle.TLabel", background=BG, foreground="#d7d7d7", font=("Arial", 10))
        style.configure("PanelTitle.TLabel", background=BG, foreground=FG, font=("Arial", 11, "bold"))
        style.configure("Muted.TLabel", background=BG, foreground="#d7d7d7", font=("Arial", 10))
        style.configure("TLabelframe", background=BG, foreground=FG, bordercolor="#5a5a5a")
        style.configure("TLabelframe.Label", background=BG, foreground=FG, font=("Arial", 10, "bold"))
        style.configure("TEntry", fieldbackground="#f5f5f5", foreground="#111111", padding=6)
        style.configure("TCombobox", fieldbackground="#f5f5f5", foreground="#111111", padding=6)
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", "#f5f5f5")],
            selectbackground=[("readonly", ACCENT)],
            selectforeground=[("readonly", FG)],
        )
        style.configure("TCheckbutton", background=BG, foreground=FG)
        style.map("TCheckbutton", background=[("active", BG)], foreground=[("active", FG)])
        style.configure("TRadiobutton", background=BG, foreground=FG)
        style.map("TRadiobutton", background=[("active", BG)], foreground=[("active", FG)])
        style.configure(
            "TProgressbar",
            troughcolor="#1e1e1e",
            background=ACCENT,
            lightcolor=ACCENT,
            darkcolor=ACCENT,
            bordercolor=BG,
        )

    def build_ui(self) -> None:
        container = ttk.Frame(self.root, padding=10)
        container.pack(fill="both", expand=True)

        header = ttk.Frame(container, padding=(10, 10, 10, 4))
        header.pack(fill="x")
        if self.logo_image is not None:
            tk.Label(header, image=self.logo_image, background=BG).pack(anchor="center", pady=(0, 8))
        ttk.Label(header, text=APP_TITLE, style="Title.TLabel").pack(anchor="center")
        ttk.Label(
            header,
            text="Herramienta de cifrado RSA para comprimir carpetas o archivos en ZIP y recuperarlos con private key.",
            style="Subtitle.TLabel",
            justify="center",
        ).pack(anchor="center", pady=(4, 0))
        tk.Frame(header, bg=ACCENT, height=2).pack(fill="x", pady=(10, 0))

        menu = ttk.Frame(container, padding=(10, 8))
        menu.pack(fill="x")
        self.add_menu_button(menu, 0, "Codificar", "encrypt")
        self.add_menu_button(menu, 1, "Decodificar", "decrypt")
        self.add_menu_button(menu, 2, "Generar llaves", "keys")
        for column in range(3):
            menu.columnconfigure(column, weight=1, uniform="menu")

        panel_holder = ttk.Frame(container, padding=(10, 6))
        panel_holder.pack(fill="both", expand=True)

        self.panels["encrypt"] = ttk.Frame(panel_holder)
        self.panels["decrypt"] = ttk.Frame(panel_holder)
        self.panels["keys"] = ttk.Frame(panel_holder)

        self.build_encrypt_panel(self.panels["encrypt"])
        self.build_decrypt_panel(self.panels["decrypt"])
        self.build_keys_panel(self.panels["keys"])

        footer = ttk.Frame(container, padding=(10, 8))
        footer.pack(fill="x")
        self.progress = ttk.Progressbar(footer, mode="indeterminate", length=150)
        self.progress.pack(side="right", padx=(10, 0))
        tk.Label(
            footer,
            textvariable=self.status_var,
            bg=STATUS_BG,
            fg=FG,
            anchor="w",
            padx=10,
            pady=10,
        ).pack(side="left", fill="x", expand=True)

        self.show_panel("encrypt")

    def add_menu_button(self, parent: ttk.Frame, column: int, text: str, panel_name: str) -> None:
        button = ttk.Button(parent, text=text, style="Menu.TButton", command=lambda: self.show_panel(panel_name))
        button.grid(row=0, column=column, padx=6, pady=4, sticky="nsew")
        self.menu_buttons[panel_name] = button

    def show_panel(self, panel_name: str) -> None:
        for name, frame in self.panels.items():
            if name == panel_name:
                frame.pack(fill="both", expand=True)
            else:
                frame.pack_forget()

        for name, button in self.menu_buttons.items():
            button.configure(style="SelectedMenu.TButton" if name == panel_name else "Menu.TButton")

    def build_encrypt_panel(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Codificar carpeta o archivo", style="PanelTitle.TLabel").pack(anchor="w")
        ttk.Label(
            parent,
            text="El flujo replica el estilo general de Mr Bot: se arma un ZIP temporal y luego se cifra con AES-256-GCM y una public key RSA.",
            style="Muted.TLabel",
            wraplength=980,
            justify="left",
        ).pack(anchor="w", pady=(4, 10))

        source_frame = ttk.LabelFrame(parent, text="Origen", padding=10)
        source_frame.pack(fill="x", pady=(0, 8))
        source_frame.columnconfigure(1, weight=1)

        mode_frame = ttk.Frame(source_frame)
        mode_frame.grid(row=0, column=0, columnspan=3, sticky="w", padx=4, pady=(0, 6))
        ttk.Radiobutton(mode_frame, text="Carpeta", value="folder", variable=self.encrypt_source_mode).pack(
            side="left", padx=(0, 18)
        )
        ttk.Radiobutton(mode_frame, text="Archivo individual", value="file", variable=self.encrypt_source_mode).pack(
            side="left"
        )
        self.add_path_field_grid(source_frame, 1, "Ruta", self.encrypt_source_path, self.pick_encrypt_source, "Seleccionar...")

        output_frame = ttk.LabelFrame(parent, text="Llave publica y salida", padding=10)
        output_frame.pack(fill="x", pady=(0, 8))
        output_frame.columnconfigure(1, weight=1)
        self.add_path_field_grid(
            output_frame,
            0,
            "Public key RSA",
            self.encrypt_public_key_path,
            self.pick_public_key,
            "Buscar...",
        )
        self.add_path_field_grid(
            output_frame,
            1,
            "Carpeta salida",
            self.encrypt_output_dir,
            self.pick_encrypt_output_dir,
            "Seleccionar...",
        )
        ttk.Label(output_frame, text="Nombre archivo").grid(row=2, column=0, padx=4, pady=4, sticky="w")
        ttk.Entry(output_frame, textvariable=self.encrypt_output_name).grid(row=2, column=1, columnspan=2, padx=4, pady=4, sticky="ew")
        ttk.Label(
            output_frame,
            text="Si queda vacío, la app genera automáticamente el nombre final con extensión .securezip.",
            style="Muted.TLabel",
            wraplength=860,
            justify="left",
        ).grid(row=3, column=0, columnspan=3, padx=4, pady=(2, 0), sticky="w")

        actions_frame = ttk.Frame(parent, padding=(0, 6, 0, 0))
        actions_frame.pack(fill="x")
        encrypt_button = ttk.Button(actions_frame, text="Comprimir y codificar", command=self.start_encrypt)
        encrypt_button.pack(side="left")
        self.action_buttons.append(encrypt_button)

    def build_decrypt_panel(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Decodificar paquete seguro", style="PanelTitle.TLabel").pack(anchor="w")
        ttk.Label(
            parent,
            text="Recupera el ZIP con una private key RSA y, si lo deseas, extrae su contenido en la carpeta de destino.",
            style="Muted.TLabel",
            wraplength=980,
            justify="left",
        ).pack(anchor="w", pady=(4, 10))

        package_frame = ttk.LabelFrame(parent, text="Paquete cifrado", padding=10)
        package_frame.pack(fill="x", pady=(0, 8))
        package_frame.columnconfigure(1, weight=1)
        self.add_path_field_grid(
            package_frame,
            0,
            "Archivo .securezip",
            self.decrypt_input_path,
            self.pick_encrypted_file,
            "Seleccionar...",
        )

        key_frame = ttk.LabelFrame(parent, text="Private key y recuperacion", padding=10)
        key_frame.pack(fill="x", pady=(0, 8))
        key_frame.columnconfigure(1, weight=1)
        self.add_path_field_grid(
            key_frame,
            0,
            "Private key RSA",
            self.decrypt_private_key_path,
            self.pick_private_key,
            "Buscar...",
        )
        ttk.Label(key_frame, text="Password").grid(row=1, column=0, padx=4, pady=4, sticky="w")
        ttk.Entry(key_frame, textvariable=self.decrypt_private_password, show="*").grid(row=1, column=1, columnspan=2, padx=4, pady=4, sticky="ew")
        self.add_path_field_grid(
            key_frame,
            2,
            "Carpeta salida",
            self.decrypt_output_dir,
            self.pick_decrypt_output_dir,
            "Seleccionar...",
        )
        ttk.Checkbutton(
            key_frame,
            text="Extraer automaticamente el ZIP al terminar",
            variable=self.extract_after_decrypt,
        ).grid(row=3, column=0, columnspan=3, padx=4, pady=(4, 0), sticky="w")
        ttk.Label(
            key_frame,
            text="Solo se aceptan private keys RSA. Claves ED25519 o ECDSA no sirven para descifrar este formato.",
            style="Muted.TLabel",
            wraplength=860,
            justify="left",
        ).grid(row=4, column=0, columnspan=3, padx=4, pady=(4, 0), sticky="w")

        actions_frame = ttk.Frame(parent, padding=(0, 6, 0, 0))
        actions_frame.pack(fill="x")
        decrypt_button = ttk.Button(actions_frame, text="Decodificar", command=self.start_decrypt)
        decrypt_button.pack(side="left")
        self.action_buttons.append(decrypt_button)

    def build_keys_panel(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Generar llaves RSA", style="PanelTitle.TLabel").pack(anchor="w")
        ttk.Label(
            parent,
            text="Crea un par de llaves publica y privada compatible con esta aplicación, guardándolo por defecto en ./keys.",
            style="Muted.TLabel",
            wraplength=980,
            justify="left",
        ).pack(anchor="w", pady=(4, 10))

        keys_frame = ttk.LabelFrame(parent, text="Configuracion de llaves", padding=10)
        keys_frame.pack(fill="x", pady=(0, 8))
        keys_frame.columnconfigure(1, weight=1)

        ttk.Label(keys_frame, text="Nombre base").grid(row=0, column=0, padx=4, pady=4, sticky="w")
        ttk.Entry(keys_frame, textvariable=self.keys_name).grid(row=0, column=1, columnspan=2, padx=4, pady=4, sticky="ew")
        self.add_path_field_grid(
            keys_frame,
            1,
            "Carpeta salida",
            self.keys_output_dir,
            self.pick_keys_output_dir,
            "Seleccionar...",
        )
        ttk.Label(keys_frame, text="Tamaño RSA").grid(row=2, column=0, padx=4, pady=4, sticky="w")
        ttk.Combobox(
            keys_frame,
            textvariable=self.keys_size,
            values=("2048", "3072", "4096"),
            state="readonly",
        ).grid(row=2, column=1, columnspan=2, padx=4, pady=4, sticky="ew")
        ttk.Label(keys_frame, text="Password opcional").grid(row=3, column=0, padx=4, pady=4, sticky="w")
        ttk.Entry(keys_frame, textvariable=self.keys_password, show="*").grid(row=3, column=1, columnspan=2, padx=4, pady=4, sticky="ew")
        ttk.Label(
            keys_frame,
            text="Se crearán archivos <nombre>_private.pem y <nombre>_public.pem. La private key puede quedar protegida con password.",
            style="Muted.TLabel",
            wraplength=860,
            justify="left",
        ).grid(row=4, column=0, columnspan=3, padx=4, pady=(4, 0), sticky="w")

        actions_frame = ttk.Frame(parent, padding=(0, 6, 0, 0))
        actions_frame.pack(fill="x")
        generate_button = ttk.Button(actions_frame, text="Generar llaves", command=self.start_generate_keys)
        generate_button.pack(side="left")
        self.action_buttons.append(generate_button)

    def add_path_field_grid(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        variable: tk.StringVar,
        command,
        button_text: str,
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, padx=4, pady=4, sticky="w")
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(parent, text=button_text, command=command).grid(row=row, column=2, padx=4, pady=4, sticky="ew")

    def set_busy(self, busy: bool, message: str) -> None:
        state = "disabled" if busy else "normal"
        for button in self.action_buttons + list(self.menu_buttons.values()):
            button.config(state=state)
        if self.progress is not None:
            if busy:
                self.progress.start(10)
            else:
                self.progress.stop()
        self.status_var.set(message)

    def run_in_background(self, worker, success_handler) -> None:
        def wrapped() -> None:
            try:
                result = worker()
            except Exception as exc:  # noqa: BLE001
                self.root.after(0, lambda error=exc: self.handle_error(error))
                return
            self.root.after(0, lambda: success_handler(result))

        threading.Thread(target=wrapped, daemon=True).start()

    def handle_error(self, exc: Exception) -> None:
        self.set_busy(False, f"Error: {exc}")
        messagebox.showerror(APP_TITLE, str(exc))

    def start_encrypt(self) -> None:
        source_path = Path(self.encrypt_source_path.get().strip())
        public_key_path = Path(self.encrypt_public_key_path.get().strip())
        output_dir = Path(self.encrypt_output_dir.get().strip())
        custom_output_name = self.encrypt_output_name.get().strip()
        source_mode = self.encrypt_source_mode.get()

        if not source_path.exists():
            messagebox.showwarning(APP_TITLE, "Selecciona una carpeta o archivo válido.")
            return
        if source_mode == "folder" and not source_path.is_dir():
            messagebox.showwarning(APP_TITLE, "Debes seleccionar una carpeta.")
            return
        if source_mode == "file" and not source_path.is_file():
            messagebox.showwarning(APP_TITLE, "Debes seleccionar un archivo.")
            return
        if not public_key_path.is_file():
            messagebox.showwarning(APP_TITLE, "Selecciona una public key válida.")
            return

        default_name = f"{source_path.stem}.securezip"
        output_name = custom_output_name or default_name
        if not output_name.endswith(".securezip"):
            output_name += ".securezip"

        output_path = ensure_unique_path(output_dir / output_name)
        self.set_busy(True, "Comprimiendo y cifrando...")

        def worker() -> Path:
            output_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="secure_encrypter_") as temp_dir:
                temp_zip = Path(temp_dir) / f"{source_path.stem}.zip"
                if source_mode == "folder":
                    zip_folder(source_path, temp_zip)
                else:
                    zip_file(source_path, temp_zip)
                return encrypt_zip(temp_zip, public_key_path, output_path, source_mode)

        def on_success(result_path: Path) -> None:
            self.set_busy(False, f"Archivo cifrado generado en: {result_path}")
            messagebox.showinfo(
                APP_TITLE,
                f"Proceso completado.\n\nArchivo generado:\n{result_path}",
            )

        self.run_in_background(worker, on_success)

    def start_decrypt(self) -> None:
        encrypted_path = Path(self.decrypt_input_path.get().strip())
        private_key_path = Path(self.decrypt_private_key_path.get().strip())
        password = self.decrypt_private_password.get()
        output_dir = Path(self.decrypt_output_dir.get().strip())
        extract_zip = self.extract_after_decrypt.get()

        if not encrypted_path.is_file():
            messagebox.showwarning(APP_TITLE, "Selecciona un archivo cifrado válido.")
            return
        if not private_key_path.is_file():
            messagebox.showwarning(APP_TITLE, "Selecciona una private key válida.")
            return

        self.set_busy(True, "Descifrando y reconstruyendo ZIP...")

        def worker() -> tuple[Path, Path | None]:
            return decrypt_package(
                encrypted_path=encrypted_path,
                private_key_path=private_key_path,
                password=password,
                output_dir=output_dir,
                extract_zip=extract_zip,
            )

        def on_success(result: tuple[Path, Path | None]) -> None:
            zip_path, extracted_to = result
            self.set_busy(False, f"ZIP recuperado en: {zip_path}")
            message = f"ZIP recuperado:\n{zip_path}"
            if extracted_to:
                message += f"\n\nContenido extraído en:\n{extracted_to}"
            messagebox.showinfo(APP_TITLE, message)

        self.run_in_background(worker, on_success)

    def start_generate_keys(self) -> None:
        output_dir = Path(self.keys_output_dir.get().strip())
        key_name = self.keys_name.get().strip()
        password = self.keys_password.get().strip() or None

        if not key_name:
            messagebox.showwarning(APP_TITLE, "Indica un nombre base para las llaves.")
            return

        self.set_busy(True, "Generando llaves RSA...")

        def worker():
            return generate_rsa_key_pair(
                output_dir=output_dir,
                key_name=key_name,
                key_size=int(self.keys_size.get()),
                password=password,
            )

        def on_success(key_pair) -> None:
            self.set_busy(False, f"Llaves generadas en: {key_pair.public_key_path.parent}")
            self.encrypt_public_key_path.set(str(key_pair.public_key_path))
            self.decrypt_private_key_path.set(str(key_pair.private_key_path))
            messagebox.showinfo(
                APP_TITLE,
                "Llaves generadas correctamente.\n\n"
                f"Public key:\n{key_pair.public_key_path}\n\n"
                f"Private key:\n{key_pair.private_key_path}",
            )

        self.run_in_background(worker, on_success)

    def pick_encrypt_source(self) -> None:
        if self.encrypt_source_mode.get() == "folder":
            selected = filedialog.askdirectory(title="Seleccionar carpeta")
        else:
            selected = filedialog.askopenfilename(title="Seleccionar archivo")
        if selected:
            self.encrypt_source_path.set(selected)

    def pick_public_key(self) -> None:
        selected = filedialog.askopenfilename(
            title="Seleccionar public key",
            filetypes=[("PEM files", "*.pem *.pub"), ("All files", "*.*")],
        )
        if selected:
            self.encrypt_public_key_path.set(selected)

    def pick_encrypt_output_dir(self) -> None:
        selected = filedialog.askdirectory(title="Seleccionar carpeta de salida")
        if selected:
            self.encrypt_output_dir.set(selected)

    def pick_encrypted_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="Seleccionar archivo cifrado",
            filetypes=[("Secure Encrypter", "*.securezip"), ("All files", "*.*")],
        )
        if selected:
            self.decrypt_input_path.set(selected)

    def pick_private_key(self) -> None:
        selected = filedialog.askopenfilename(
            title="Seleccionar private key",
            filetypes=[("PEM files", "*.pem *.key"), ("All files", "*.*")],
        )
        if selected:
            self.decrypt_private_key_path.set(selected)

    def pick_decrypt_output_dir(self) -> None:
        selected = filedialog.askdirectory(title="Seleccionar carpeta de salida")
        if selected:
            self.decrypt_output_dir.set(selected)

    def pick_keys_output_dir(self) -> None:
        selected = filedialog.askdirectory(title="Seleccionar carpeta para guardar llaves")
        if selected:
            self.keys_output_dir.set(selected)


def main() -> None:
    root = tk.Tk()
    SecureEncrypterApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
