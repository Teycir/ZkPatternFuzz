#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$PROJECT_ROOT/scripts/load_env_master.sh"
load_env_master "$PROJECT_ROOT"

MATRIX_PATH="${1:-$PROJECT_ROOT/targets/zk0d_matrix_external_manual.yaml}"
CACHE_ROOT="${ZKFUZZ_TOOLCHAIN_CACHE_ROOT:-$PROJECT_ROOT/build/toolchains}"
SCARB_ARCHIVE_DIR="${ZK_FUZZER_SCARB_ARCHIVE_DIR:-$CACHE_ROOT/scarb_archives}"
SCARB_TOOLCHAIN_DIR="${ZK_FUZZER_SCARB_TOOLCHAIN_DIR:-$CACHE_ROOT/scarb_toolchains}"
HALO2_CARGO_HOME_SEED="${ZK_FUZZER_HALO2_CARGO_HOME_CACHE_SEED:-$CACHE_ROOT/cargo_home_seed}"
NOIR_CACHE_ROOT="${ZKFUZZ_NOIR_CACHE_ROOT:-$CACHE_ROOT/noir_cache}"
NOIR_NARGO_HOME="${ZKFUZZ_NOIR_NARGO_HOME:-$NOIR_CACHE_ROOT/nargo_home}"
NOIR_CARGO_HOME="${ZKFUZZ_NOIR_CARGO_HOME:-$NOIR_CACHE_ROOT/cargo_home}"
NOIR_TARGET_DIR="${ZKFUZZ_NOIR_TARGET_DIR:-$NOIR_CACHE_ROOT/target}"
NOIR_TOOLCHAIN_DIR="${ZK_FUZZER_NARGO_TOOLCHAIN_DIR:-$CACHE_ROOT/nargo_toolchains}"
SNARKJS_TOOLCHAIN_DIR="${ZKFUZZ_SNARKJS_TOOLCHAIN_DIR:-$CACHE_ROOT/snarkjs_toolchains}"
HALO2_GO_CACHE_ROOT="${ZKFUZZ_HALO2_GO_CACHE_ROOT:-$CACHE_ROOT/go_cache}"
HALO2_GO_PROXY_CACHE_DIR="${ZK_FUZZER_HALO2_GO_PROXY_CACHE_DIR:-$HALO2_GO_CACHE_ROOT/pkg/mod/cache/download}"
RUSTUP_HOME_PREFETCH="${RUSTUP_HOME:-$CACHE_ROOT/rustup_home}"
HOST_RUSTUP_HOME_DEFAULT="${RUSTUP_HOME:-$HOME/.rustup}"
ENV_HINTS_FILE="${ZKFUZZ_PREFETCH_ENV_HINTS_FILE:-$CACHE_ROOT/prefetch.env}"
PREFETCH_LOG_DIR="${ZKFUZZ_PREFETCH_LOG_DIR:-$CACHE_ROOT/prefetch_logs}"
PREFETCH_DIAG_REPORT="${ZKFUZZ_PREFETCH_DIAG_REPORT:-$CACHE_ROOT/prefetch_diagnostics.log}"

mkdir -p \
  "$SCARB_ARCHIVE_DIR" \
  "$SCARB_TOOLCHAIN_DIR" \
  "$HALO2_CARGO_HOME_SEED" \
  "$NOIR_NARGO_HOME" \
  "$NOIR_CARGO_HOME" \
  "$NOIR_TARGET_DIR" \
  "$NOIR_TOOLCHAIN_DIR" \
  "$SNARKJS_TOOLCHAIN_DIR" \
  "$HALO2_GO_PROXY_CACHE_DIR" \
  "$RUSTUP_HOME_PREFETCH" \
  "$PREFETCH_LOG_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required"
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required"
  exit 1
fi

echo "[prefetch] matrix: $MATRIX_PATH"
echo "[prefetch] cache root: $CACHE_ROOT"
echo "# prefetch diagnostics $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$PREFETCH_DIAG_REPORT"
echo -e "framework\tphase\tmanifest\ttoolchain\tcode\tsource\thint\tlog" >> "$PREFETCH_DIAG_REPORT"

append_unique() {
  local -n arr_ref="$1"
  local value="$2"
  [[ -z "$value" ]] && return
  for existing in "${arr_ref[@]:-}"; do
    if [[ "$existing" == "$value" ]]; then
      return
    fi
  done
  arr_ref+=("$value")
}

parse_list_into_array() {
  local raw="${1:-}"
  local -n out_ref="$2"
  raw="${raw//;/,}"
  IFS=',' read -r -a tokens <<< "$raw"
  for token in "${tokens[@]}"; do
    token="${token#"${token%%[![:space:]]*}"}"
    token="${token%"${token##*[![:space:]]}"}"
    [[ -z "$token" ]] && continue
    append_unique out_ref "$token"
  done
}

join_csv() {
  local -n arr_ref="$1"
  local IFS=,
  echo "${arr_ref[*]}"
}

join_paths() {
  local -n arr_ref="$1"
  local IFS=':'
  echo "${arr_ref[*]}"
}

resolve_candidate_path() {
  local candidate="$1"
  if [[ "$candidate" == */* ]]; then
    if [[ -x "$candidate" ]]; then
      echo "$candidate"
    fi
    return 0
  fi
  command -v "$candidate" 2>/dev/null || true
}

probe_plain_binary() {
  local candidate="$1"
  local resolved
  resolved="$(resolve_candidate_path "$candidate")"
  [[ -n "$resolved" ]] || return 1
  "$resolved" --version >/dev/null 2>&1 || return 1
  echo "$resolved"
}

probe_snarkjs_binary() {
  local candidate="$1"
  local resolved
  resolved="$(resolve_candidate_path "$candidate")"
  [[ -n "$resolved" ]] || return 1
  if [[ "$resolved" == *.js ]]; then
    node "$resolved" --version >/dev/null 2>&1 || return 1
  else
    "$resolved" --version >/dev/null 2>&1 || return 1
  fi
  echo "$resolved"
}

noir_manifest_package_name() {
  local manifest="$1"
  python3 - "$manifest" <<'PY'
import pathlib, sys
try:
    import tomllib
except Exception:
    tomllib = None

manifest = pathlib.Path(sys.argv[1])
if not manifest.is_file() or tomllib is None:
    sys.exit(0)
try:
    doc = tomllib.loads(manifest.read_text(encoding="utf-8"))
except Exception:
    sys.exit(0)
pkg = doc.get("package") or {}
name = pkg.get("name")
if isinstance(name, str) and name.strip():
    print(name.strip())
PY
}

noir_workspace_roots_for_manifest() {
  local manifest="$1"
  python3 - "$manifest" <<'PY'
import pathlib, sys
try:
    import tomllib
except Exception:
    tomllib = None

manifest = pathlib.Path(sys.argv[1]).resolve()
project_dir = manifest.parent
if tomllib is None:
    sys.exit(0)

seen = set()
for parent in [project_dir, *project_dir.parents]:
    nargo = parent / "Nargo.toml"
    if not nargo.is_file():
        continue
    try:
        doc = tomllib.loads(nargo.read_text(encoding="utf-8"))
    except Exception:
        continue
    workspace = doc.get("workspace")
    if not isinstance(workspace, dict):
        continue
    members = workspace.get("members")
    if not isinstance(members, list):
        continue
    for member in members:
        if not isinstance(member, str) or not member.strip():
            continue
        candidate = (parent / member).resolve()
        if candidate == project_dir:
            key = str(parent)
            if key not in seen:
                seen.add(key)
                print(key)
            break
PY
}

halo2_manifest_needs_prefetch_sanitize() {
  local manifest="$1"
  python3 - "$manifest" <<'PY'
import pathlib, re, sys
raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="ignore")
needs_fragment = re.search(r'git\s*=\s*"[^"]*#[^"]*"', raw) is not None
needs_patch = re.search(r'^\[patch\.', raw, re.M) is not None
print("1" if (needs_fragment or needs_patch) else "0")
PY
}

sanitize_halo2_manifest_for_prefetch() {
  local manifest="$1"
  python3 - "$manifest" <<'PY'
import pathlib, re, sys
path = pathlib.Path(sys.argv[1])
raw = path.read_text(encoding="utf-8", errors="ignore")

# Rewrite malformed git URLs that embed commit fragments in the URL itself.
raw = re.sub(
    r'git\s*=\s*"([^"#]+)#[^"]*"',
    lambda m: f'git = "{m.group(1)}"',
    raw,
)

# Drop patch sections for prefetch fallback only.
# Some third-party manifests carry patch blocks that become self-source conflicts
# after URL sanitation and block dependency fetch entirely.
raw = re.sub(
    r'^\[patch\.[^\n]*\]\n(?:^(?!\[).*(?:\n|$))*',
    '',
    raw,
    flags=re.M,
)

path.write_text(raw, encoding="utf-8")
PY
}

run_halo2_cargo_fetch_attempt() {
  local manifest="$1"
  local tc="$2"
  local needs_next_lock_bump="$3"
  local tc_arg="+${tc}"

  if [[ "$needs_next_lock_bump" == "true" ]]; then
    RUSTUP_HOME="$RUSTUP_HOME_FOR_FETCH" \
      CARGO_HOME="$HALO2_CARGO_HOME_SEED" \
      CARGO_NET_GIT_FETCH_WITH_CLI=true \
      cargo "$tc_arg" -Znext-lockfile-bump fetch --manifest-path "$manifest"
  else
    RUSTUP_HOME="$RUSTUP_HOME_FOR_FETCH" \
      CARGO_HOME="$HALO2_CARGO_HOME_SEED" \
      CARGO_NET_GIT_FETCH_WITH_CLI=true \
      cargo "$tc_arg" fetch --manifest-path "$manifest"
  fi
}

run_halo2_sanitized_fetch_fallback() {
  local manifest="$1"
  local tc="$2"
  local needs_next_lock_bump="$3"

  local cache_tmp_dir="$CACHE_ROOT/prefetch_tmp"
  mkdir -p "$cache_tmp_dir"
  local temp_root
  temp_root="$(mktemp -d "$cache_tmp_dir/halo2_manifest.XXXXXX")"
  local manifest_backup="$temp_root/Cargo.toml.orig"
  local lock_path
  lock_path="$(dirname "$manifest")/Cargo.lock"
  local lock_backup=""

  cp "$manifest" "$manifest_backup"
  if [[ -f "$lock_path" ]]; then
    lock_backup="$temp_root/Cargo.lock.orig"
    mv "$lock_path" "$lock_backup"
  fi

  sanitize_halo2_manifest_for_prefetch "$manifest"

  local status=0
  if run_halo2_cargo_fetch_attempt "$manifest" "$tc" "$needs_next_lock_bump"; then
    status=0
  else
    status=$?
  fi

  cp "$manifest_backup" "$manifest"
  if [[ -n "$lock_backup" && -f "$lock_backup" ]]; then
    mv "$lock_backup" "$lock_path"
  fi
  rm -rf "$temp_root"

  return "$status"
}

sanitize_label() {
  local raw="$1"
  local sanitized
  sanitized="$(echo "$raw" | tr '/: .' '____' | tr -cd '[:alnum:]_-' | cut -c1-120)"
  if [[ -z "$sanitized" ]]; then
    sanitized="unknown"
  fi
  echo "$sanitized"
}

classify_prefetch_error() {
  local framework="$1"
  local log_file="$2"

  local code="UNKNOWN_FAILURE"
  local source="unknown"
  local hint="Inspect full log and upstream manifest/toolchain pins."

  if rg -q "dns error|Could not resolve host|failed to lookup address information" "$log_file"; then
    code="NETWORK_DNS_FAILURE"
    source="network/dns"
    hint="Check DNS/connectivity and rerun prefetch."
  elif rg -q "Selected package .* was not found" "$log_file"; then
    code="NOIR_PACKAGE_NOT_FOUND"
    source="noir workspace/package selection"
    hint="Run nargo from the correct workspace root or pin the package entrypoint."
  elif rg -q "Expected an expression but found '@'|Internal Compiler Error: Error node encountered" "$log_file"; then
    code="NOIR_TOOLCHAIN_SYNTAX_MISMATCH"
    source="noir compiler version mismatch"
    hint="Install/select nargo/noirc matching target compiler features."
  elif rg -q "not valid: is this a git repository" "$log_file"; then
    code="HALO2_GIT_URL_FRAGMENT_INVALID"
    source="Cargo.toml malformed git URL with fragment"
    hint="Rewrite git URL fragment into clean git URL + rev in target manifest."
  elif rg -q "patch for .* points to the same source" "$log_file"; then
    code="HALO2_PATCH_SOURCE_CONFLICT"
    source="Cargo patch section"
    hint="Patch source matches dependency source; adjust or remove the conflicting patch."
  elif rg -q "failed to select a version for the requirement" "$log_file"; then
    code="HALO2_DEP_VERSION_CONFLICT"
    source="dependency constraints"
    hint="Pin compatible dependency/revision in Cargo.toml or refresh lockfile."
  elif rg -q "failed to parse revision specifier" "$log_file"; then
    code="HALO2_INVALID_REV_SPEC"
    source="Cargo.lock git revision entry"
    hint="Regenerate Cargo.lock after correcting git dependency fields."
  elif rg -q "invalid value|Invalid value" "$log_file"; then
    code="TOOL_ARG_INVALID"
    source="command arguments"
    hint="Check command arguments and tool version compatibility."
  fi

  echo "$code|$source|$hint"
}

emit_granular_error() {
  local framework="$1"
  local phase="$2"
  local manifest="$3"
  local toolchain="$4"
  local log_file="$5"

  local parsed
  parsed="$(classify_prefetch_error "$framework" "$log_file")"
  local code="${parsed%%|*}"
  local rest="${parsed#*|}"
  local source="${rest%%|*}"
  local hint="${rest#*|}"

  echo "[prefetch][error][$framework][$phase] manifest=$manifest toolchain=$toolchain code=$code source=$source hint=$hint log=$log_file"
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$framework" "$phase" "$manifest" "$toolchain" "$code" "$source" "$hint" "$log_file" >> "$PREFETCH_DIAG_REPORT"
}

mapfile -t CAIRO_MANIFESTS < <(python3 - "$MATRIX_PATH" <<'PY'
import os, re, sys, yaml
matrix = sys.argv[1]
with open(matrix, "r", encoding="utf-8") as fh:
    doc = yaml.safe_load(fh) or {}
for t in doc.get("targets", []):
    if not t.get("enabled", True):
        continue
    if (t.get("framework") or "").lower() != "cairo":
        continue
    tc = t.get("target_circuit") or ""
    manifest = None
    if tc.endswith("Scarb.toml") and os.path.isfile(tc):
        manifest = tc
    else:
        cur = os.path.dirname(tc)
        while cur and cur != "/":
            cand = os.path.join(cur, "Scarb.toml")
            if os.path.isfile(cand):
                manifest = cand
                break
            nxt = os.path.dirname(cur)
            if nxt == cur:
                break
            cur = nxt
    if manifest:
        print(manifest)
PY
)

mapfile -t HALO2_MANIFESTS < <(python3 - "$MATRIX_PATH" <<'PY'
import os, sys, yaml
matrix = sys.argv[1]
with open(matrix, "r", encoding="utf-8") as fh:
    doc = yaml.safe_load(fh) or {}
for t in doc.get("targets", []):
    if not t.get("enabled", True):
        continue
    if (t.get("framework") or "").lower() != "halo2":
        continue
    tc = t.get("target_circuit") or ""
    if tc.endswith("Cargo.toml") and os.path.isfile(tc):
        print(tc)
PY
)

mapfile -t NOIR_MANIFESTS < <(python3 - "$MATRIX_PATH" <<'PY'
import os, sys, yaml
matrix = sys.argv[1]
with open(matrix, "r", encoding="utf-8") as fh:
    doc = yaml.safe_load(fh) or {}
for t in doc.get("targets", []):
    if not t.get("enabled", True):
        continue
    if (t.get("framework") or "").lower() != "noir":
        continue
    tc = t.get("target_circuit") or ""
    if tc.endswith("Nargo.toml") and os.path.isfile(tc):
        print(tc)
PY
)

mapfile -t CIRCOM_TARGETS < <(python3 - "$MATRIX_PATH" <<'PY'
import os, sys, yaml
matrix = sys.argv[1]
with open(matrix, "r", encoding="utf-8") as fh:
    doc = yaml.safe_load(fh) or {}
for t in doc.get("targets", []):
    if not t.get("enabled", True):
        continue
    if (t.get("framework") or "").lower() != "circom":
        continue
    tc = t.get("target_circuit") or ""
    if tc.endswith(".circom") and os.path.isfile(tc):
        print(tc)
PY
)

mapfile -t SCARB_VERSIONS < <(python3 - "${CAIRO_MANIFESTS[@]}" <<'PY'
import os, re, sys
seen = set()
for path in sys.argv[1:]:
    if not os.path.isfile(path):
        continue
    raw = open(path, "r", encoding="utf-8", errors="ignore").read()
    m = re.search(r'^\s*cairo-version\s*=\s*["\']([^"\']+)["\']\s*$', raw, re.M)
    if not m:
        continue
    v = m.group(1).strip()
    if v and v not in seen:
        seen.add(v)
        print(v)
PY
)

if [[ ${#SCARB_VERSIONS[@]} -eq 0 ]]; then
  echo "[prefetch] no cairo-version found in matrix; skipping Scarb archive download"
fi

host_triples=()
case "$(uname -m):$(uname -s)" in
  x86_64:Linux)
    host_triples=("x86_64-unknown-linux-gnu" "x86_64-unknown-linux-musl")
    ;;
  aarch64:Linux)
    host_triples=("aarch64-unknown-linux-gnu" "aarch64-unknown-linux-musl")
    ;;
  x86_64:Darwin)
    host_triples=("x86_64-apple-darwin")
    ;;
  arm64:Darwin|aarch64:Darwin)
    host_triples=("aarch64-apple-darwin")
    ;;
  *)
    echo "[prefetch] unknown host, no default Scarb triples: $(uname -m):$(uname -s)"
    ;;
esac

download_scarb_archive() {
  local version="$1"
  local triple="$2"
  local archive_name="scarb-v${version}-${triple}.tar.gz"
  local archive_path="$SCARB_ARCHIVE_DIR/$archive_name"
  local url="https://github.com/software-mansion/scarb/releases/download/v${version}/${archive_name}"
  if [[ -s "$archive_path" ]]; then
    echo "[prefetch] archive exists: $archive_name"
  else
    echo "[prefetch] downloading: $archive_name"
    curl -fL --retry 2 --connect-timeout 10 --max-time 600 -o "$archive_path" "$url"
  fi
  local extract_dir="$SCARB_TOOLCHAIN_DIR/scarb-v${version}-${triple}"
  if [[ -x "$extract_dir/bin/scarb" ]]; then
    echo "[prefetch] toolchain exists: scarb-v${version}-${triple}"
  else
    echo "[prefetch] extracting: $archive_name"
    tar -xzf "$archive_path" -C "$SCARB_TOOLCHAIN_DIR"
  fi
}

for version in "${SCARB_VERSIONS[@]:-}"; do
  for triple in "${host_triples[@]:-}"; do
    download_scarb_archive "$version" "$triple"
  done
done

working_nargo_bins=()
if command -v nargo >/dev/null 2>&1; then
  append_unique working_nargo_bins "$(command -v nargo)"
fi
if [[ -n "${ZK_FUZZER_NARGO_BIN_CANDIDATES:-}" ]]; then
  env_nargo_candidates=()
  parse_list_into_array "$ZK_FUZZER_NARGO_BIN_CANDIDATES" env_nargo_candidates
  for candidate in "${env_nargo_candidates[@]}"; do
    if resolved="$(probe_plain_binary "$candidate")"; then
      append_unique working_nargo_bins "$resolved"
    fi
  done
fi

if compgen -G "$NOIR_TOOLCHAIN_DIR/nargo-*" >/dev/null 2>&1; then
  for candidate in "$NOIR_TOOLCHAIN_DIR"/nargo-*; do
    if resolved="$(probe_plain_binary "$candidate")"; then
      append_unique working_nargo_bins "$resolved"
    fi
  done
fi

if [[ -n "${ZK_FUZZER_NARGO_PREFETCH_VERSIONS:-}" ]]; then
  requested_nargo_versions=()
  parse_list_into_array "$ZK_FUZZER_NARGO_PREFETCH_VERSIONS" requested_nargo_versions
  if [[ ${#requested_nargo_versions[@]} -gt 0 ]]; then
    if ! command -v noirup >/dev/null 2>&1; then
      echo "[prefetch] warn: noirup missing, cannot prefetch requested nargo versions"
    else
      current_nargo_version="$(nargo --version 2>/dev/null | awk -F'= ' '/^nargo version/{print $2; exit}' | tr -d '[:space:]')"
      for version in "${requested_nargo_versions[@]}"; do
        local_copy="$NOIR_TOOLCHAIN_DIR/nargo-$version"
        if [[ -x "$local_copy" ]]; then
          echo "[prefetch] nargo version cached: $version"
        else
          echo "[prefetch] noirup install nargo version: $version"
          if noirup -v "$version"; then
            if resolved="$(probe_plain_binary nargo)"; then
              cp "$resolved" "$local_copy"
              chmod +x "$local_copy"
              echo "[prefetch] cached nargo-$version at $local_copy"
            else
              echo "[prefetch] warn: noirup completed but nargo binary probe failed for $version"
            fi
          else
            echo "[prefetch] warn: noirup failed for version $version"
          fi
        fi
        if [[ -x "$local_copy" ]]; then
          append_unique working_nargo_bins "$local_copy"
        fi
      done
      if [[ -n "$current_nargo_version" ]]; then
        noirup -v "$current_nargo_version" >/dev/null 2>&1 || true
      fi
    fi
  fi
fi

if [[ ${#NOIR_MANIFESTS[@]} -gt 0 ]]; then
  if [[ ${#working_nargo_bins[@]} -eq 0 ]]; then
    echo "[prefetch] warn: noir targets found but no usable nargo binary found"
  else
    nargo_for_prefetch="${working_nargo_bins[0]}"
    echo "[prefetch] noir prefetch using: $nargo_for_prefetch"
    for manifest in "${NOIR_MANIFESTS[@]}"; do
      [[ -f "$manifest" ]] || continue
      project_dir="$(dirname "$manifest")"
      manifest_label="$(sanitize_label "$manifest")"
      echo "[prefetch] nargo compile for: $manifest"
      primary_log="$PREFETCH_LOG_DIR/noir_primary_${manifest_label}.log"
      if (
        cd "$project_dir"
        HOME="$NOIR_NARGO_HOME" \
          NARGO_HOME="$NOIR_NARGO_HOME" \
          CARGO_HOME="$NOIR_CARGO_HOME" \
          NARGO_TARGET_DIR="$NOIR_TARGET_DIR" \
          CARGO_TARGET_DIR="$NOIR_TARGET_DIR" \
          "$nargo_for_prefetch" compile
      ) >"$primary_log" 2>&1; then
        cat "$primary_log"
        continue
      fi

      package_missing=false
      if rg -q "Selected package .* was not found" "$primary_log"; then
        package_missing=true
      fi
      cat "$primary_log"
      emit_granular_error "NOIR" "compile_primary" "$manifest" "$nargo_for_prefetch" "$primary_log"

      fallback_succeeded=false
      final_failure_phase="compile_primary"
      final_failure_log="$primary_log"
      if $package_missing; then
        package_name="$(noir_manifest_package_name "$manifest" || true)"
        mapfile -t workspace_roots < <(noir_workspace_roots_for_manifest "$manifest")
        for workspace_root in "${workspace_roots[@]:-}"; do
          workspace_label="$(sanitize_label "$workspace_root")"
          if [[ -n "$package_name" ]]; then
            echo "[prefetch] noir fallback: $workspace_root --package $package_name"
            fallback_log="$PREFETCH_LOG_DIR/noir_fallback_package_${manifest_label}_${workspace_label}.log"
            if (
              cd "$workspace_root"
              HOME="$NOIR_NARGO_HOME" \
                NARGO_HOME="$NOIR_NARGO_HOME" \
                CARGO_HOME="$NOIR_CARGO_HOME" \
                NARGO_TARGET_DIR="$NOIR_TARGET_DIR" \
                CARGO_TARGET_DIR="$NOIR_TARGET_DIR" \
                "$nargo_for_prefetch" compile --package "$package_name"
            ) >"$fallback_log" 2>&1; then
              cat "$fallback_log"
              fallback_succeeded=true
              break
            fi
            cat "$fallback_log"
            emit_granular_error "NOIR" "compile_package_fallback" "$manifest" "$nargo_for_prefetch" "$fallback_log"
            final_failure_phase="compile_package_fallback"
            final_failure_log="$fallback_log"
          fi

          echo "[prefetch] noir fallback: $workspace_root --workspace"
          fallback_log="$PREFETCH_LOG_DIR/noir_fallback_workspace_${manifest_label}_${workspace_label}.log"
          if (
            cd "$workspace_root"
            HOME="$NOIR_NARGO_HOME" \
              NARGO_HOME="$NOIR_NARGO_HOME" \
              CARGO_HOME="$NOIR_CARGO_HOME" \
              NARGO_TARGET_DIR="$NOIR_TARGET_DIR" \
              CARGO_TARGET_DIR="$NOIR_TARGET_DIR" \
              "$nargo_for_prefetch" compile --workspace
          ) >"$fallback_log" 2>&1; then
            cat "$fallback_log"
            fallback_succeeded=true
            break
          fi
          cat "$fallback_log"
          emit_granular_error "NOIR" "compile_workspace_fallback" "$manifest" "$nargo_for_prefetch" "$fallback_log"
          final_failure_phase="compile_workspace_fallback"
          final_failure_log="$fallback_log"
        done
      fi

      if ! $fallback_succeeded; then
        echo "[prefetch] warn: nargo compile failed for $manifest"
        emit_granular_error "NOIR" "$final_failure_phase" "$manifest" "$nargo_for_prefetch" "$final_failure_log"
      fi
    done
  fi
fi

working_circom_bins=()
if command -v circom >/dev/null 2>&1; then
  append_unique working_circom_bins "$(command -v circom)"
fi
if [[ -n "${ZK_FUZZER_CIRCOM_BIN_CANDIDATES:-}" ]]; then
  env_circom_candidates=()
  parse_list_into_array "$ZK_FUZZER_CIRCOM_BIN_CANDIDATES" env_circom_candidates
  for candidate in "${env_circom_candidates[@]}"; do
    if resolved="$(probe_plain_binary "$candidate")"; then
      append_unique working_circom_bins "$resolved"
    fi
  done
fi

working_snarkjs_bins=()
if command -v snarkjs >/dev/null 2>&1; then
  append_unique working_snarkjs_bins "$(command -v snarkjs)"
fi
if [[ -n "${ZK_FUZZER_SNARKJS_PATH_CANDIDATES:-}" ]]; then
  env_snarkjs_candidates=()
  parse_list_into_array "$ZK_FUZZER_SNARKJS_PATH_CANDIDATES" env_snarkjs_candidates
  for candidate in "${env_snarkjs_candidates[@]}"; do
    if resolved="$(probe_snarkjs_binary "$candidate")"; then
      append_unique working_snarkjs_bins "$resolved"
    fi
  done
fi

if [[ -n "${ZK_FUZZER_SNARKJS_PREFETCH_VERSIONS:-}" ]]; then
  requested_snarkjs_versions=()
  parse_list_into_array "$ZK_FUZZER_SNARKJS_PREFETCH_VERSIONS" requested_snarkjs_versions
  if [[ ${#requested_snarkjs_versions[@]} -gt 0 ]]; then
    if ! command -v npm >/dev/null 2>&1; then
      echo "[prefetch] warn: npm missing, cannot prefetch requested snarkjs versions"
    else
      for version in "${requested_snarkjs_versions[@]}"; do
        prefix="$SNARKJS_TOOLCHAIN_DIR/snarkjs-$version"
        bin_path="$prefix/node_modules/.bin/snarkjs"
        if [[ -x "$bin_path" ]]; then
          echo "[prefetch] snarkjs version cached: $version"
        else
          echo "[prefetch] npm install snarkjs@$version"
          mkdir -p "$prefix"
          npm install --prefix "$prefix" "snarkjs@$version" >/dev/null 2>&1 || {
            echo "[prefetch] warn: npm install failed for snarkjs@$version"
          }
        fi
        if [[ -x "$bin_path" ]]; then
          append_unique working_snarkjs_bins "$bin_path"
        fi
      done
    fi
  fi
fi

if [[ ${#CIRCOM_TARGETS[@]} -gt 0 ]]; then
  if [[ ${#working_circom_bins[@]} -eq 0 ]]; then
    echo "[prefetch] warn: circom targets found but no usable circom binary found"
  fi
  if [[ ${#working_snarkjs_bins[@]} -eq 0 ]]; then
    echo "[prefetch] warn: circom targets found but no usable snarkjs binary found (runtime may fallback to npx)"
  fi
fi

ptau_dirs=()
for candidate in \
  "$PROJECT_ROOT/bins/ptau" \
  "$PROJECT_ROOT/tests/circuits/build"
do
  if [[ -d "$candidate" ]] && compgen -G "$candidate/*.ptau" >/dev/null 2>&1; then
    append_unique ptau_dirs "$candidate"
  fi
done
for circuit in "${CIRCOM_TARGETS[@]:-}"; do
  circuit_dir="$(dirname "$circuit")"
  for candidate in "$circuit_dir" "$circuit_dir/../ptau" "$circuit_dir/../build"; do
    if [[ -d "$candidate" ]] && compgen -G "$candidate/*.ptau" >/dev/null 2>&1; then
      append_unique ptau_dirs "$candidate"
    fi
  done
done

if command -v rustup >/dev/null 2>&1; then
  default_halo2_toolchains=(
    "stable"
    "nightly"
    "nightly-2023-12-21"
    "nightly-2024-02-08"
    "nightly-2024-07-07"
    "nightly-2025-12-01"
    "1.82.0"
    "1.85"
  )
  IFS=',' read -r -a env_halo2_toolchains <<< "${ZK_FUZZER_HALO2_CARGO_TOOLCHAIN_CANDIDATES:-}"
  halo2_toolchains=()
  for tc in "${env_halo2_toolchains[@]}" "${default_halo2_toolchains[@]}"; do
    tc="${tc//[$'\t\r\n ']}"
    [[ -z "$tc" ]] && continue
    if [[ " ${halo2_toolchains[*]} " != *" $tc "* ]]; then
      halo2_toolchains+=("$tc")
    fi
  done
  for tc in "${halo2_toolchains[@]}"; do
    echo "[prefetch] rustup toolchain install: $tc"
    RUSTUP_HOME="$RUSTUP_HOME_PREFETCH" \
    rustup toolchain install "$tc" --profile minimal || echo "[prefetch] warn: install failed: $tc"
  done
else
  echo "[prefetch] rustup not found; skipping rust toolchain prefetch"
fi

prefetch_rustup_ready=false
if [[ -d "$RUSTUP_HOME_PREFETCH/toolchains" ]] && compgen -G "$RUSTUP_HOME_PREFETCH/toolchains/*" >/dev/null 2>&1; then
  prefetch_rustup_ready=true
fi

RUSTUP_HOME_FOR_FETCH="$RUSTUP_HOME_PREFETCH"
if ! $prefetch_rustup_ready; then
  if [[ "$HOST_RUSTUP_HOME_DEFAULT" != "$RUSTUP_HOME_PREFETCH" ]] \
    && [[ -d "$HOST_RUSTUP_HOME_DEFAULT/toolchains" ]] \
    && compgen -G "$HOST_RUSTUP_HOME_DEFAULT/toolchains/*" >/dev/null 2>&1; then
    RUSTUP_HOME_FOR_FETCH="$HOST_RUSTUP_HOME_DEFAULT"
    echo "[prefetch] local rustup cache is empty; using host rustup home for cargo prefetch: $RUSTUP_HOME_FOR_FETCH"
  fi
fi

if command -v cargo >/dev/null 2>&1; then
  IFS=',' read -r -a env_halo2_toolchains <<< "${ZK_FUZZER_HALO2_CARGO_TOOLCHAIN_CANDIDATES:-}"
  halo2_try_toolchains=()
  for tc in "${env_halo2_toolchains[@]}" "nightly" "nightly-2024-07-07" "stable"; do
    tc="${tc//[$'\t\r\n ']}"
    [[ -z "$tc" ]] && continue
    if [[ " ${halo2_try_toolchains[*]} " != *" $tc "* ]]; then
      halo2_try_toolchains+=("$tc")
    fi
  done

  for manifest in "${HALO2_MANIFESTS[@]:-}"; do
    [[ -f "$manifest" ]] || continue
    echo "[prefetch] cargo fetch for: $manifest"
    manifest_label="$(sanitize_label "$manifest")"
    fetched=false
    manifest_needs_sanitize=false
    if [[ "$(halo2_manifest_needs_prefetch_sanitize "$manifest")" == "1" ]]; then
      manifest_needs_sanitize=true
    fi
    lock_path="$(dirname "$manifest")/Cargo.lock"
    needs_next_lock_bump=false
    if [[ -f "$lock_path" ]] && rg -q '^version\s*=\s*4\s*$' "$lock_path"; then
      needs_next_lock_bump=true
    fi
    for tc in "${halo2_try_toolchains[@]}"; do
      if $needs_next_lock_bump && [[ "$tc" != nightly* ]]; then
        continue
      fi
      echo "  - trying toolchain: $tc"
      tc_label="$(sanitize_label "$tc")"
      fetch_log="$PREFETCH_LOG_DIR/halo2_fetch_${manifest_label}_${tc_label}.log"
      if run_halo2_cargo_fetch_attempt "$manifest" "$tc" "$needs_next_lock_bump" >"$fetch_log" 2>&1; then
        cat "$fetch_log"
        fetched=true
        break
      fi
      cat "$fetch_log"
      emit_granular_error "HALO2" "cargo_fetch" "$manifest" "$tc" "$fetch_log"
      if $manifest_needs_sanitize; then
        echo "    - retrying with sanitized manifest fallback"
        sanitized_fetch_log="$PREFETCH_LOG_DIR/halo2_fetch_sanitized_${manifest_label}_${tc_label}.log"
        if run_halo2_sanitized_fetch_fallback "$manifest" "$tc" "$needs_next_lock_bump" >"$sanitized_fetch_log" 2>&1; then
          cat "$sanitized_fetch_log"
          fetched=true
          break
        fi
        cat "$sanitized_fetch_log"
        emit_granular_error "HALO2" "cargo_fetch_sanitized" "$manifest" "$tc" "$sanitized_fetch_log"
      fi
    done
    if ! $fetched; then
      echo "[prefetch] warn: could not prefetch deps for $manifest"
    fi
  done
else
  echo "[prefetch] cargo not found; skipping halo2 dependency prefetch"
fi

if command -v go >/dev/null 2>&1; then
  for manifest in "${HALO2_MANIFESTS[@]:-}"; do
    [[ -f "$manifest" ]] || continue
    project_dir="$(dirname "$manifest")"
    if [[ ! -f "$project_dir/go.mod" ]]; then
      continue
    fi
    echo "[prefetch] go mod download for: $project_dir/go.mod"
    GOPATH="$HALO2_GO_CACHE_ROOT" \
      GOMODCACHE="$HALO2_GO_CACHE_ROOT/pkg/mod" \
      GOCACHE="$HALO2_GO_CACHE_ROOT/cache" \
      go mod download -C "$project_dir" || {
        echo "[prefetch] warn: go mod download failed for $project_dir"
      }
  done
fi

{
cat <<EOF
export ZK_FUZZER_SCARB_ARCHIVE_DIR="$SCARB_ARCHIVE_DIR"
export ZK_FUZZER_SCARB_TOOLCHAIN_DIR="$SCARB_TOOLCHAIN_DIR"
export ZK_FUZZER_SCARB_AUTO_DOWNLOAD=false
export ZK_FUZZER_HALO2_CARGO_HOME_CACHE_SEED="$HALO2_CARGO_HOME_SEED"
export ZK_FUZZER_HALO2_AUTO_ONLINE_RETRY=true
export ZK_FUZZER_HALO2_GO_PROXY_CACHE_DIR="$HALO2_GO_PROXY_CACHE_DIR"
EOF
if $prefetch_rustup_ready; then
  echo "export RUSTUP_HOME=\"$RUSTUP_HOME_PREFETCH\""
fi
if [[ ${#working_nargo_bins[@]} -gt 0 ]]; then
  echo "export ZK_FUZZER_NARGO_BIN_CANDIDATES=\"$(join_csv working_nargo_bins)\""
fi
if [[ ${#working_circom_bins[@]} -gt 0 ]]; then
  echo "export ZK_FUZZER_CIRCOM_BIN_CANDIDATES=\"$(join_csv working_circom_bins)\""
fi
if [[ ${#working_snarkjs_bins[@]} -gt 0 ]]; then
  echo "export ZK_FUZZER_SNARKJS_PATH_CANDIDATES=\"$(join_csv working_snarkjs_bins)\""
fi
if [[ ${#ptau_dirs[@]} -gt 0 ]]; then
  echo "export ZK_FUZZER_CIRCOM_PTAU_SEARCH_PATHS=\"$(join_paths ptau_dirs)\""
fi
} > "$ENV_HINTS_FILE"

echo "[prefetch] wrote env hints: $ENV_HINTS_FILE"
echo "[prefetch] diagnostics report: $PREFETCH_DIAG_REPORT"
echo "[prefetch] done"
