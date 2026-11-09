import os
import zipfile
from pathlib import Path

import pytest

from pdgseg.errors import PdgsegError
from pdgseg.packager import build_zip, is_excluded


def names(zip_path: Path):
    with zipfile.ZipFile(zip_path) as zf:
        return sorted(zf.namelist())


def tree(root: Path, *files: str) -> Path:
    for rel in files:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")
    return root


def test_default_excludes_skip_vcs_and_dependencies(project: Path, tmp_path: Path):
    package = build_zip(project, tmp_path / "out.zip")
    assert names(package.path) == [".pdgseg.yml", "src/app.py", "src/dao.java"]
    assert package.file_count == 3


def test_configured_excludes(tmp_path: Path):
    root = tree(tmp_path / "p", "src/a.py", "dist/bundle.js", "web/app.min.js", "web/app.js",
                "docs/guia.md", "docs/sub/otra.md", "src/gen/x.py", "src/gen/sub/y.py", "build/out/z.class")
    package = build_zip(root, tmp_path / "out.zip",
                        ["dist/", "*.min.js", "docs/**", "src/gen/*.py", "build"])
    assert names(package.path) == ["src/a.py", "src/gen/sub/y.py", "web/app.js"]


@pytest.mark.parametrize("rel, is_dir, pattern, expected", [
    ("a/dist", True, "dist/", True),           # a folder pattern matches at any level
    ("dist.py", False, "dist/", False),        # ...but not a file with that name
    ("a/dist/x.js", False, "dist/", True),     # ...and covers the files inside
    ("src/x.min.js", False, "*.min.js", True),
    ("docs/a/b.md", False, "docs/**", True),
    ("other/docs/b.md", False, "/docs/", False),   # a leading "/" anchors to the root
    ("docs/b.md", False, "/docs/", True),
    ("src/gen/sub/y.py", False, "src/gen/*.py", False),  # "*" does not cross folders
    ("src/gen/sub/y.py", False, "src/**/*.py", True),
])
def test_patterns(rel, is_dir, pattern, expected):
    assert is_excluded(rel, is_dir, [pattern]) is expected


def test_zip_uses_forward_slashes(tmp_path: Path):
    root = tree(tmp_path / "p", "a/b/c.txt")
    assert names(build_zip(root, tmp_path / "out.zip").path) == ["a/b/c.txt"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="sin enlaces simbólicos")
def test_symlinks_are_not_followed(tmp_path: Path):
    outside = tree(tmp_path / "fuera", "secreto.txt")
    root = tree(tmp_path / "p", "a.txt")
    try:
        os.symlink(outside, root / "enlace", target_is_directory=True)
        os.symlink(outside / "secreto.txt", root / "secreto.txt")
    except OSError:
        pytest.skip("crear enlaces simbólicos requiere permisos en este sistema")
    assert names(build_zip(root, tmp_path / "out.zip").path) == ["a.txt"]


def test_nothing_to_analyze_is_an_error(tmp_path: Path):
    root = tree(tmp_path / "p", "node_modules/x.js")
    with pytest.raises(PdgsegError, match="No hay archivos que analizar"):
        build_zip(root, tmp_path / "out.zip")


def test_too_large_is_an_error_that_suggests_excludes(tmp_path: Path):
    root = tmp_path / "p"
    root.mkdir()
    (root / "big.bin").write_bytes(os.urandom(4096))
    with pytest.raises(PdgsegError, match="Agrega a «exclude»"):
        build_zip(root, tmp_path / "out.zip", max_bytes=1024)


def test_the_zip_itself_is_never_included(tmp_path: Path):
    root = tree(tmp_path / "p", "a.txt")
    assert names(build_zip(root, root / "self.zip").path) == ["a.txt"]
