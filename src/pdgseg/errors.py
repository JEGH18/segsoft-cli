"""Errores técnicos: todos terminan el CLI con exit code 10."""

from __future__ import annotations

from typing import Optional


class PdgsegError(Exception):
    """Un error técnico con un mensaje para mostrar tal cual al usuario."""


class ConfigError(PdgsegError):
    """.pdgseg.yml no existe, no es YAML válido o no cumple el schema."""


class ApiError(PdgsegError):
    """El backend respondió con un error, o no se pudo conectar con él."""

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status
