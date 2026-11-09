"""Comprime el directorio a analizar en un ZIP, respetando las exclusiones."""

from __future__ import annotations

import os
import re
import zipfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

from .errors import PdgsegError

MAX_ZIP_BYTES = 100 * 1024 * 1024  # spring.servlet.multipart.max-file-size of the backend

# Never worth uploading: VCS data, dependencies, virtualenvs, caches and IDE settings.
DEFAULT_EXCLUDES: Tuple[str, ...] = (
    ".git/", ".hg/", ".svn/",
    "node_modules/", ".venv/", "venv/", "__pycache__/", ".pytest_cache/", ".mypy_cache/", ".tox/",
    ".idea/", ".vscode/", ".DS_Store",
)


@dataclass(frozen=True)
class Package:
    path: Path
    file_count: int
    size_bytes: int


def build_zip(root: Path, dest: Path, excludes: Sequence[str] = (),
              max_bytes: int = MAX_ZIP_BYTES) -> Package:
    """
    Comprime los archivos de root (rutas relativas a root, con «/») en dest.
    No sigue enlaces simbólicos: un enlace podría sacar archivos de fuera del repositorio.
    """
    root = root.resolve()
    if not root.is_dir():
        raise PdgsegError(f"{root} no es un directorio.")
    patterns = list(DEFAULT_EXCLUDES) + [p for p in excludes if p.strip()]
    dest_resolved = dest.resolve()

    count = 0
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path, rel in _walk(root, patterns):
            if file_path.resolve() == dest_resolved:
                continue
            zf.write(file_path, rel)
            count += 1

    size = dest.stat().st_size
    if count == 0:
        raise PdgsegError(f"No hay archivos que analizar en {root} (¿las exclusiones lo cubren todo?).")
    if size > max_bytes:
        raise PdgsegError(
            f"El ZIP del proyecto pesa {size / 1024 / 1024:.1f} MB y el máximo es {max_bytes // 1024 // 1024} MB. "
            f"Agrega a «exclude» en .pdgseg.yml las carpetas que no son código fuente (builds, datos, binarios).")
    return Package(path=dest, file_count=count, size_bytes=size)


def _walk(root: Path, patterns: List[str]) -> Iterator[Tuple[Path, str]]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        rel_dir = current.relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir

        kept = []
        for name in sorted(dirnames):
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if (current / name).is_symlink() or is_excluded(rel, True, patterns):
                continue
            kept.append(name)
        dirnames[:] = kept  # prune in place so os.walk does not descend

        for name in sorted(filenames):
            full = current / name
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if full.is_symlink() or is_excluded(rel, False, patterns):
                continue
            yield full, rel


def is_excluded(rel_path: str, is_dir: bool, patterns: Iterable[str]) -> bool:
    """
    Subconjunto de .gitignore (sin negaciones):
      - «*.min.js», «build»: sin «/», se compara con el nombre, en cualquier nivel;
      - «dist/»: solo carpetas; «docs/**»: todo lo que hay dentro de docs;
      - «src/gen/*.py», «/config»: con «/» (al inicio o en medio), se compara desde la raíz;
      - «*» no cruza carpetas, «**» sí, «?» es un carácter.
    Excluir una carpeta excluye todo lo que contiene.
    """
    parts = rel_path.split("/")
    # The path itself and each of its parent folders: (path from the root, name, is a folder).
    candidates = [("/".join(parts[:i]), parts[i - 1], i < len(parts) or is_dir) for i in range(1, len(parts) + 1)]
    for raw in patterns:
        rule = _compile(raw)
        if rule is None:
            continue
        regex, anchored, dir_only = rule
        for sub, name, is_folder in candidates:
            if dir_only and not is_folder:
                continue
            if regex.fullmatch(sub if anchored else name):
                return True
    return False


@lru_cache(maxsize=256)
def _compile(raw: str) -> Optional[Tuple["re.Pattern[str]", bool, bool]]:
    pattern = raw.strip()
    dir_only = pattern.endswith("/")
    pattern = pattern.rstrip("/")
    anchored = "/" in pattern  # decided before dropping "/**": "docs/**" is anchored, "dist/" is not
    if pattern.endswith("/**"):
        pattern, dir_only = pattern[:-3], True
    pattern = pattern.lstrip("/")
    if not pattern:
        return None
    return re.compile(_glob_to_regex(pattern)), anchored, dir_only


def _glob_to_regex(glob: str) -> str:
    out, i = [], 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return "".join(out)
