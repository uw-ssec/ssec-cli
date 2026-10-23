import json
from pathlib import Path

DEFAULT_PKGS = {"pip": "24.0", "certifi": "2025.8.3"}


def _dist_info(site: Path, name: str, version: str) -> None:
    d = site / f"{name.replace('-', '_')}-{version}.dist-info"
    d.mkdir(parents=True, exist_ok=True)
    (d / "METADATA").write_text(f"Name: {name}\nVersion: {version}\n")


def make_venv(
    root: Path,
    *,
    uv: bool = False,
    pkgs: dict[str, str] | None = None,
    py: str = "3.12",
    windows: bool = False,
) -> Path:
    pkgs = DEFAULT_PKGS if pkgs is None else pkgs
    root.mkdir(parents=True, exist_ok=True)
    cfg = f"home = /usr/bin\nversion = {py}.1\n"
    if uv:
        cfg += "uv = 0.13.4\n"
    (root / "pyvenv.cfg").write_text(cfg)
    if windows:
        site = root / "Lib" / "site-packages"
        (root / "Scripts").mkdir(exist_ok=True)
        (root / "Scripts" / "python.exe").write_text("")
    else:
        site = root / "lib" / f"python{py}" / "site-packages"
        (root / "bin").mkdir(exist_ok=True)
        (root / "bin" / "python").write_text("")
    site.mkdir(parents=True, exist_ok=True)
    for name, version in pkgs.items():
        _dist_info(site, name, version)
    return root


def make_conda_env(
    root: Path,
    pkgs: dict[str, str],
    pip_pkgs: dict[str, str] | None = None,
    py: str = "3.12.1",
) -> Path:
    meta = root / "conda-meta"
    meta.mkdir(parents=True, exist_ok=True)
    (meta / "history").write_text("")
    for name, version in {"python": py, **pkgs}.items():
        (meta / f"{name}-{version}-h0_0.json").write_text(
            json.dumps({"name": name, "version": version})
        )
    major_minor = ".".join(py.split(".")[:2])
    site = root / "lib" / f"python{major_minor}" / "site-packages"
    site.mkdir(parents=True, exist_ok=True)
    for name, version in (pip_pkgs or {}).items():
        _dist_info(site, name, version)
    return root


def make_framework(root: Path, version: str) -> Path:
    """Create `<root>/<version>` shaped like a Python.framework version dir."""
    env = root / version
    site = env / "lib" / f"python{version}" / "site-packages"
    site.mkdir(parents=True, exist_ok=True)
    (env / "bin").mkdir(exist_ok=True)
    (env / "bin" / "python3").write_text("")
    _dist_info(site, "pip", "24.0")
    return env
