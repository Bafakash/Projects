#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

url_dataset_path="URL dataset.csv"
phishing_dataset_path="Phishing URLs.csv"
skip_install=0
skip_offline_export=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url-dataset)
      url_dataset_path="$2"
      shift 2
      ;;
    --phishing-dataset)
      phishing_dataset_path="$2"
      shift 2
      ;;
    --skip-install)
      skip_install=1
      shift
      ;;
    --skip-offline-export)
      skip_offline_export=1
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

ensure_dataset() {
  local expected_name="$1"
  local candidate_path="$2"

  if [[ -f "$expected_name" ]]; then
    echo "Found $expected_name in repo root."
    return
  fi

  if [[ ! -f "$candidate_path" ]]; then
    echo "Missing $expected_name. Place it in repo root or pass its path via script args." >&2
    exit 1
  fi

  local source_abs target_abs
  source_abs="$(realpath "$candidate_path")"
  target_abs="$(realpath -m "$expected_name")"

  if [[ "$source_abs" == "$target_abs" ]]; then
    echo "Using existing $expected_name."
    return
  fi

  cp -f "$source_abs" "$target_abs"
  echo "Copied $expected_name from: $source_abs"
}

ensure_dataset "URL dataset.csv" "$url_dataset_path"
ensure_dataset "Phishing URLs.csv" "$phishing_dataset_path"

if [[ "$skip_install" -eq 0 ]]; then
  python -m pip install -r requirements.txt
fi

python train.py

if [[ "$skip_offline_export" -eq 0 ]]; then
  python export_offline_model.py
fi

echo
echo "Model artifacts generated:"
echo "- ensemble_models.pkl"
echo "- model.pkl"
echo "- vectorizer.pkl"
echo "- training_report.json"
if [[ "$skip_offline_export" -eq 0 ]]; then
  echo "- offline/model.js + offline/model.json"
fi
