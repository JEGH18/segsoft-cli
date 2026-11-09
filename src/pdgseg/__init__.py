"""pdgseg: CLI de SegSoft para ejecutar el análisis de cumplimiento desde pipelines CI/CD."""

try:
    from importlib.metadata import PackageNotFoundError, version

    __version__ = version("pdgseg-cli")
except PackageNotFoundError:  # running from a source tree without installing
    __version__ = "0.0.0.dev0"
