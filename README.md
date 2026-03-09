# Secure Encrypter

Aplicación de escritorio en Python con `tkinter` para:

- seleccionar una carpeta y comprimirla en ZIP antes de cifrarla con una `public key`
- seleccionar un archivo individual, comprimirlo en ZIP y cifrarlo con una `public key`
- descifrar el paquete con la `private key`, reconstruyendo el ZIP y opcionalmente extrayéndolo

## Requisitos

- Python 3.11 o superior recomendado
- dependencias de `requirements.txt`
- claves RSA en formato PEM

## Instalación

```bash
pip install -r requirements.txt
```

## Ejecución

```bash
python app.py
```

## Generar llaves

Para crear un par de llaves RSA compatible con la aplicación y guardarlo en `./keys`:

```bash
python3 key_manager.py
```

Esto genera por defecto:

- `keys/secure_encrypter_private.pem`
- `keys/secure_encrypter_public.pem`

Opciones útiles:

```bash
python3 key_manager.py --name cliente_a --key-size 4096
python3 key_manager.py --name cliente_b --password mi_password
```

## Ejecutables y releases

Build local:

```bash
pip install -r requirements.txt
pip install pyinstaller
./build_linux.sh
```

En Windows:

```powershell
pip install -r requirements.txt
pip install pyinstaller
.\build_windows.ps1
```

GitHub Actions:

- el workflow está en `.github/workflows/release-zips-on-tag.yml`
- se ejecuta al pushear un tag con formato `YYYYMMDD` o `YYYYMMDD_HHMMSS`
- genera ZIPs para Linux y Windows con el ejecutable, `bin/` y `README.md`

## Formato de trabajo

1. La app crea un ZIP temporal del archivo o carpeta elegidos.
2. Ese ZIP se cifra con AES-256-GCM.
3. La clave AES se cifra con la `public key` RSA.
4. El resultado se guarda con extensión `.securezip`.

Para descifrar, la app usa la `private key`, recupera el ZIP y puede extraerlo automáticamente.
