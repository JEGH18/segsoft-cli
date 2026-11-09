"""Punto de entrada: «pdgseg analyze»."""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path
from typing import Optional

import click

from . import __version__
from .client import ApiClient
from .config import CONFIG_FILE_NAME, SERVER_ENV, example_config, load_config
from .errors import PdgsegError
from .flow import Progress, run_analysis
from .output import error_json, render_text, to_json
from .summary import EXIT_ERROR, EXIT_OK, exit_code_for, summarize

TOKEN_ENV = "PDGSEG_API_TOKEN"
DEFAULT_SARIF_PATH = "results.sarif"


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="pdgseg")
def main() -> None:
    """CLI de SegSoft: análisis de cumplimiento de seguridad para pipelines CI/CD."""
    _utf8_when_redirected()


def _utf8_when_redirected() -> None:
    """
    On Windows, output redirected to a pipe or file (a CI log) uses the ANSI code page, so accents
    show up garbled and a character outside it would crash. CI logs are read as UTF-8: write UTF-8
    there. An interactive console is left alone (click writes to it through the Unicode console API).
    """
    for stream in (sys.stdout, sys.stderr):
        if not hasattr(stream, "reconfigure"):
            continue
        try:
            if stream.isatty():
                stream.reconfigure(errors="replace")
            else:
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError, AttributeError):
            pass


@main.command()
@click.option("--path", "path", type=click.Path(file_okay=False, dir_okay=True, path_type=Path), default=".",
              show_default=True, help="Directorio del proyecto a analizar.")
@click.option("--config", "config_path", type=click.Path(dir_okay=False, path_type=Path), default=None,
              help=f"Archivo de configuración. Por defecto, {CONFIG_FILE_NAME} dentro de --path.")
@click.option("--output", "output_format", type=click.Choice(["text", "json", "sarif"]), default="text",
              show_default=True, help="text: resumen legible; json: para scripts; sarif: archivo SARIF 2.1.0 "
                                      "(para GitHub Code Scanning) más el resumen en texto.")
@click.option("--output-path", type=click.Path(dir_okay=False, path_type=Path), default=None,
              help=f"Dónde escribir la salida json o sarif (sarif: {DEFAULT_SARIF_PATH} por defecto; "
                   "json: la salida estándar por defecto).")
@click.option("--dry-run", is_flag=True, help="Analiza e informa, pero devuelve 0 aunque haya hallazgos "
                                              "(los errores técnicos siguen devolviendo 10).")
@click.option("--quiet", "-q", is_flag=True, help="Sin mensajes de progreso ni colores.")
@click.option("--verbose", "-v", is_flag=True, help="Muestra cada petición HTTP y el detalle de los errores.")
@click.option("--token", envvar=TOKEN_ENV, default=None, show_envvar=True,
              help=f"Token de API (pdgseg_...). Mejor por la variable {TOKEN_ENV}: lo que va en la línea de "
                   "comandos puede quedar en el historial y en los logs.")
@click.option("--server", envvar=SERVER_ENV, default=None, show_envvar=True,
              help="URL del backend; reemplaza «server» de la configuración.")
def analyze(path: Path, config_path: Optional[Path], output_format: str, output_path: Optional[Path],
            dry_run: bool, quiet: bool, verbose: bool, token: Optional[str], server: Optional[str]) -> None:
    """Sube el proyecto, ejecuta el análisis y termina con un código de salida según los hallazgos.

    \b
    Códigos de salida:
      0   sin hallazgos de la severidad failOnSeverity (por defecto high) o superior
      1   hallazgos de esa severidad o superior, sin CRITICAL
      2   al menos un hallazgo CRITICAL
      10  error técnico (configuración, token, red, análisis fallido)
    """
    if quiet and verbose:
        raise click.UsageError("--quiet y --verbose no se pueden usar juntos.")

    json_to_stdout = output_format == "json" and output_path is None
    color = not quiet and output_format != "json" and sys.stdout.isatty() and "NO_COLOR" not in os.environ

    def info(message: str) -> None:
        if not quiet:
            click.echo(message, err=True)

    def debug(message: str) -> None:
        if verbose:
            click.echo(click.style(message, dim=True) if color else message, err=True)

    def fail(message: str) -> None:
        if json_to_stdout:
            click.echo(error_json(message, EXIT_ERROR))
        click.echo(("Error: " if not message.startswith("Error") else "") + message, err=True)
        sys.exit(EXIT_ERROR)

    try:
        config = load_config(config_path or (path / CONFIG_FILE_NAME), server_override=server)
        if not token:
            raise PdgsegError(f"Falta el token de API: defínelo en la variable {TOKEN_ENV} (en CI, como secreto) "
                              f"o con --token. Se crea en SegSoft, ícono de llave, «Tokens de API».")
        token = token.strip()
        if dry_run:
            click.echo(click.style("DRY-RUN: el resultado no hará fallar el pipeline.", fg="yellow", bold=True)
                       if color else "DRY-RUN: el resultado no hará fallar el pipeline.", err=True)

        info(f"pdgseg {__version__} -> {config.server}")
        client = ApiClient(config.server, token, log=debug)
        outcome = run_analysis(client, config, path, want_sarif=output_format == "sarif", progress=Progress(info))
    except PdgsegError as e:
        fail(str(e))
        return
    except KeyboardInterrupt:
        fail("Interrumpido.")
        return
    except Exception as e:  # noqa: BLE001 - any bug must still end in exit code 10, not a traceback
        if verbose:
            traceback.print_exc()
        fail(f"Error inesperado: {e}")
        return

    summary = summarize(outcome.results)
    real_code = exit_code_for(summary, config.fail_on_severity)
    code = EXIT_OK if dry_run else real_code

    sarif_path = None
    if output_format == "sarif":
        sarif_path = output_path or Path(DEFAULT_SARIF_PATH)
        try:
            sarif_path.parent.mkdir(parents=True, exist_ok=True)
            sarif_path.write_bytes(outcome.sarif or b"")
        except OSError as e:
            fail(f"No se pudo escribir {sarif_path}: {e}")
        info(f"SARIF escrito en {sarif_path}")

    if output_format == "json":
        document = to_json(outcome, summary, exit_code=code, real_exit_code=real_code,
                           fail_on_severity=config.fail_on_severity, dry_run=dry_run)
        if output_path:
            try:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(document + "\n", encoding="utf-8")
            except OSError as e:
                fail(f"No se pudo escribir {output_path}: {e}")
            info(f"JSON escrito en {output_path}")
        else:
            click.echo(document)
    else:
        click.echo(render_text(outcome, summary, exit_code=code, real_exit_code=real_code,
                               fail_on_severity=config.fail_on_severity, dry_run=dry_run,
                               server=config.server, color=color))
    sys.exit(code)


@main.command("init")
@click.option("--path", "path", type=click.Path(file_okay=False, path_type=Path), default=".", show_default=True)
def init(path: Path) -> None:
    """Crea un .pdgseg.yml de ejemplo (no sobrescribe uno existente)."""
    target = path / CONFIG_FILE_NAME
    if target.exists():
        click.echo(f"{target} ya existe; no se modificó.", err=True)
        sys.exit(EXIT_ERROR)
    target.write_text(example_config(), encoding="utf-8")
    click.echo(f"Creado {target}. Ajusta «server» y «policySet».")


if __name__ == "__main__":  # pragma: no cover
    main()
