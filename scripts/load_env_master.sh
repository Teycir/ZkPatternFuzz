#!/usr/bin/env bash
# shellcheck shell=bash

load_env_master() {
  local project_root="${1:-}"
  local env_master="${ZKF_ENV_MASTER_FILE:-}"

  if [[ -z "$env_master" && -n "$project_root" ]]; then
    local candidate
    for candidate in "$project_root/.env.master" "$project_root/.env.paths" "$project_root/.env"; do
      if [[ -f "$candidate" ]]; then
        env_master="$candidate"
        break
      fi
    done
  fi

  if [[ -n "$env_master" ]]; then
    if [[ "$env_master" == "~/"* ]]; then
      env_master="$HOME/${env_master#~/}"
    elif [[ "$env_master" == "~" ]]; then
      env_master="$HOME"
    fi
    if [[ "$env_master" != /* && -n "$project_root" ]]; then
      env_master="$project_root/$env_master"
    fi
  fi

  if [[ -z "$env_master" ]]; then
    return 0
  fi

  if [[ ! -f "$env_master" ]]; then
    echo "[WARN] Env master file not found: $env_master" >&2
    return 0
  fi

  set -a
  # shellcheck disable=SC1090
  source "$env_master"
  set +a
}
