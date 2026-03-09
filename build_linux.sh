#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_root"

dist_path="$project_root/Ejecutable"
work_path="$project_root/temp_build"

pyinstaller="pyinstaller"
if [ -x "$project_root/venv/bin/pyinstaller" ]; then
  pyinstaller="$project_root/venv/bin/pyinstaller"
fi

python_cmd="python3"
if [ -x "$project_root/venv/bin/python" ]; then
  python_cmd="$project_root/venv/bin/python"
elif ! command -v "$python_cmd" >/dev/null 2>&1; then
  python_cmd="python"
fi

if ! command -v "$pyinstaller" >/dev/null 2>&1; then
  echo "Error: pyinstaller no encontrado. Activa el venv o instala pyinstaller." >&2
  exit 1
fi

if ! command -v "$python_cmd" >/dev/null 2>&1; then
  echo "Error: python no encontrado. Activa el venv o instala Python." >&2
  exit 1
fi

echo "=== Compilando Secure Encrypter ==="

icon_path="$project_root/bin/ABP-blanco-en-fondo-negro.ico"

"$pyinstaller" \
  --noconfirm \
  --clean \
  --onefile \
  --windowed \
  --distpath "$dist_path" \
  --workpath "$work_path" \
  --specpath "$work_path" \
  --name "secure-encrypter" \
  --icon "$icon_path" \
  "$project_root/app.py"

echo "=== Copiando archivos adicionales ==="

install -d "$dist_path/bin"
cp -a "$project_root/bin/." "$dist_path/bin/"

if [ -f "$project_root/README.md" ]; then
  cp -a "$project_root/README.md" "$dist_path/README.md"
fi

echo "Ejecutable creado en: $dist_path"
