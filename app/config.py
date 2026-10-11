"""Configuration loading.

Defaults live in reviewer.yml next to the app. A reviewed project may put its
own reviewer.yml in its root to override individual keys.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

APP_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = APP_ROOT / "reviewer.yml"
DATA_DIR = Path(os.getenv("REVIEWER_DATA_DIR", APP_ROOT / "data"))


def ui_settings_path() -> Path:
    """Settings saved from the dashboard's settings page (layered over reviewer.yml)."""
    return DATA_DIR / "settings.yml"

try:  # load .env so API keys never have to live in code
    from dotenv import load_dotenv

    load_dotenv(APP_ROOT / ".env")
except Exception:  # pragma: no cover - dotenv is optional
    pass


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _read_yaml(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return data


def load_config(project_root: Optional[str | Path] = None, overrides: Optional[Dict[str, Any]] = None,
                ui_settings: bool = True) -> Dict[str, Any]:
    """Effective config: reviewer.yml < settings saved in the dashboard < the project's
    reviewer.yml < explicit overrides."""
    cfg = _read_yaml(DEFAULT_CONFIG_PATH)
    if ui_settings:
        cfg = _deep_merge(cfg, read_ui_settings())
    if project_root:
        project_file = Path(project_root) / "reviewer.yml"
        if project_file.resolve() != DEFAULT_CONFIG_PATH.resolve():
            cfg = _deep_merge(cfg, _read_yaml(project_file))
    if overrides:
        cfg = _deep_merge(cfg, overrides)
    return cfg


def allowed_roots(cfg: Dict[str, Any]) -> list[Path]:
    env = os.getenv("REVIEWER_ALLOWED_ROOTS", "").strip()
    roots = [p for p in env.split(os.pathsep) if p.strip()] if env else []
    roots += list((cfg.get("server") or {}).get("allowed_roots") or [])
    if not roots:
        roots = [str(Path.home())]
    return [Path(r).expanduser().resolve() for r in roots]


def read_ui_settings() -> Dict[str, Any]:
    try:
        return _read_yaml(ui_settings_path())
    except (OSError, ValueError, yaml.YAMLError):
        return {}


def write_ui_settings(data: Dict[str, Any]) -> None:
    path = ui_settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write("# Saved from the dashboard's settings page. Overrides reviewer.yml; delete to reset.\n")
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True)
    os.replace(tmp, path)
