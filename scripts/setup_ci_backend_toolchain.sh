#!/usr/bin/env bash
set -euo pipefail

PROFILE="${1:-full}"

CIRCOM_VERSION="${CIRCOM_VERSION:-2.2.3}"
SNARKJS_VERSION="${SNARKJS_VERSION:-0.7.6}"
NARGO_VERSION="${NARGO_VERSION:-1.0.0-beta.18}"
SCARB_VERSION="${SCARB_VERSION:-2.15.1}"
CAIRO_LANG_VERSION="${CAIRO_LANG_VERSION:-0.14.0.1}"

BIN_DIR="${HOME}/.local/bin"
CACHE_DIR="${HOME}/.local/share/zkpatternfuzz-ci"
TMP_DIR="${RUNNER_TEMP:-/tmp}/zkpatternfuzz-ci"
PYTHON_BIN="${PYTHON_BIN:-}"

if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "python interpreter not found in PATH" >&2
    exit 1
  fi
fi

mkdir -p "$BIN_DIR" "$CACHE_DIR" "$TMP_DIR"
export PATH="$BIN_DIR:$HOME/.cargo/bin:$PATH"

if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$BIN_DIR" >>"$GITHUB_PATH"
  printf '%s\n' "$HOME/.cargo/bin" >>"$GITHUB_PATH"
fi

apt_packages=()
if [[ "$PROFILE" == "full" ]] \
  && ! command -v bubblewrap >/dev/null 2>&1 \
  && ! command -v bwrap >/dev/null 2>&1; then
  apt_packages+=(bubblewrap)
fi
if [[ "$PROFILE" == "full" ]] && ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
  apt_packages+=(python3-venv)
fi

if ((${#apt_packages[@]} > 0)); then
  sudo apt-get update
  sudo apt-get install -y "${apt_packages[@]}"
fi

download() {
  local url="$1"
  local output="$2"

  curl --fail --location --retry 5 --retry-delay 2 --retry-connrefused "$url" -o "$output"
}

first_non_empty_line() {
  awk 'NF { print; exit }'
}

python_version_string() {
  "$1" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'
}

python_version_at_least() {
  "$1" - "$2" "$3" <<'PY'
import sys

major = int(sys.argv[1])
minor = int(sys.argv[2])
sys.exit(0 if sys.version_info >= (major, minor) else 1)
PY
}

ensure_cairo_lang_python_compatibility() {
  if [[ "$CAIRO_LANG_VERSION" != "0.14.0.1" ]]; then
    return
  fi

  if python_version_at_least "$PYTHON_BIN" 3 11; then
    local version
    version="$(python_version_string "$PYTHON_BIN")"
    echo \
      "cairo-lang ${CAIRO_LANG_VERSION} is incompatible with Python ${version}; set PYTHON_BIN to Python 3.10." \
      >&2
    exit 1
  fi
}

probe_snarkjs_version() {
  local line
  line="$(snarkjs --version 2>&1 | first_non_empty_line || true)"
  if [[ -n "$line" ]]; then
    printf '%s\n' "$line"
    return 0
  fi

  line="$(snarkjs --help 2>&1 | first_non_empty_line || true)"
  if [[ -n "$line" ]]; then
    printf '%s\n' "$line"
    return 0
  fi

  return 1
}

install_circom() {
  if command -v circom >/dev/null 2>&1 && circom --version 2>/dev/null | grep -Fq "$CIRCOM_VERSION"; then
    return
  fi

  download \
    "https://github.com/iden3/circom/releases/download/v${CIRCOM_VERSION}/circom-linux-amd64" \
    "$BIN_DIR/circom"
  chmod +x "$BIN_DIR/circom"
}

install_snarkjs() {
  local current_version
  current_version="$(probe_snarkjs_version || true)"
  if [[ "$current_version" == *"$SNARKJS_VERSION"* ]]; then
    return
  fi

  npm install --global --prefix "$HOME/.local" "snarkjs@${SNARKJS_VERSION}"
}

install_nargo() {
  if command -v nargo >/dev/null 2>&1 && nargo --version 2>/dev/null | grep -Fq "$NARGO_VERSION"; then
    return
  fi

  local archive="$TMP_DIR/nargo-${NARGO_VERSION}.tar.gz"
  download \
    "https://github.com/noir-lang/noir/releases/download/v${NARGO_VERSION}/nargo-x86_64-unknown-linux-gnu.tar.gz" \
    "$archive"
  tar -xzf "$archive" -C "$TMP_DIR"
  install -m 0755 "$TMP_DIR/nargo" "$BIN_DIR/nargo"
}

install_scarb() {
  if command -v scarb >/dev/null 2>&1 && scarb --version 2>/dev/null | grep -Fq "$SCARB_VERSION"; then
    return
  fi

  local archive="$TMP_DIR/scarb-${SCARB_VERSION}.tar.gz"
  local extract_dir="$TMP_DIR/scarb-${SCARB_VERSION}"

  rm -rf "$extract_dir"
  mkdir -p "$extract_dir"
  download \
    "https://github.com/software-mansion/scarb/releases/download/v${SCARB_VERSION}/scarb-v${SCARB_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
    "$archive"
  tar -xzf "$archive" -C "$extract_dir"

  local scarb_root="$extract_dir/scarb-v${SCARB_VERSION}-x86_64-unknown-linux-gnu/bin"
  install -m 0755 "$scarb_root/scarb" "$BIN_DIR/scarb"
  install -m 0755 "$scarb_root/scarb-cairo-language-server" "$BIN_DIR/scarb-cairo-language-server"
  install -m 0755 "$scarb_root/scarb-cairo-test" "$BIN_DIR/scarb-cairo-test"
  install -m 0755 "$scarb_root/scarb-doc" "$BIN_DIR/scarb-doc"
  install -m 0755 "$scarb_root/scarb-execute" "$BIN_DIR/scarb-execute"
  install -m 0755 "$scarb_root/scarb-mdbook" "$BIN_DIR/scarb-mdbook"
  install -m 0755 "$scarb_root/scarb-prove" "$BIN_DIR/scarb-prove"
  install -m 0755 "$scarb_root/scarb-verify" "$BIN_DIR/scarb-verify"
}

install_cairo_lang() {
  if command -v cairo-compile >/dev/null 2>&1 \
    && command -v cairo-run >/dev/null 2>&1 \
    && cairo-compile --version 2>/dev/null | grep -Fq "$CAIRO_LANG_VERSION" \
    && cairo-run --version 2>/dev/null | grep -Fq "$CAIRO_LANG_VERSION"; then
    return
  fi

  ensure_cairo_lang_python_compatibility

  local venv_dir="$CACHE_DIR/cairo-lang-${CAIRO_LANG_VERSION}"
  local archive="$TMP_DIR/cairo-lang-${CAIRO_LANG_VERSION}.zip"
  rm -rf "$venv_dir"
  download \
    "https://github.com/starkware-libs/cairo-lang/releases/download/v${CAIRO_LANG_VERSION}/cairo-lang-${CAIRO_LANG_VERSION}.zip" \
    "$archive"
  "$PYTHON_BIN" -m venv "$venv_dir"
  "$venv_dir/bin/python" -m pip install --upgrade pip setuptools wheel
  "$venv_dir/bin/python" -m pip install "$archive"

  ln -sf "$venv_dir/bin/cairo-compile" "$BIN_DIR/cairo-compile"
  ln -sf "$venv_dir/bin/cairo-run" "$BIN_DIR/cairo-run"
}

verify_circom_profile() {
  command -v circom >/dev/null 2>&1
  command -v snarkjs >/dev/null 2>&1
  circom --version
  probe_snarkjs_version
}

verify_full_profile() {
  command -v bubblewrap >/dev/null 2>&1 || command -v bwrap >/dev/null 2>&1
  command -v circom >/dev/null 2>&1
  command -v snarkjs >/dev/null 2>&1
  command -v nargo >/dev/null 2>&1
  command -v scarb >/dev/null 2>&1
  command -v cairo-compile >/dev/null 2>&1
  command -v cairo-run >/dev/null 2>&1

  circom --version
  probe_snarkjs_version
  nargo --version
  scarb --version
  cairo-compile --version
  cairo-run --version
}

case "$PROFILE" in
  circom)
    install_circom
    install_snarkjs
    hash -r
    verify_circom_profile
    ;;
  full)
    install_circom
    install_snarkjs
    install_nargo
    install_scarb
    install_cairo_lang
    hash -r
    verify_full_profile
    ;;
  *)
    echo "unsupported profile: $PROFILE" >&2
    exit 1
    ;;
esac
