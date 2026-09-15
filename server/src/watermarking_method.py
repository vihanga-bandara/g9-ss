"""watermarking_method.py

Abstract base classes and common utilities for PDF watermarking methods.

This module defines the interface that all watermarking methods must
implement, along with a few lightweight helpers that concrete
implementations can import. The goal is to keep the contract stable and
clear, while leaving algorithmic details up to each method.

Design highlights
-----------------
- Modern Python (3.10+), with type hints and docstrings.
- Standard library only in this file. Concrete methods may optionally
  depend on third‑party libraries such as *PyMuPDF* (a.k.a. ``fitz``).
- Stateless API: methods receive a PDF input and return a new PDF as
  ``bytes``; no in‑place mutation or file I/O is required by the
  interface (callers may choose to write the returned bytes to disk).

Required interface
------------------
Concrete implementations must subclass :class:`WatermarkingMethod` and
implement the two abstract methods:

``add_watermark(pdf, secret, key, position) -> bytes``
    Produce a new watermarked PDF (as ``bytes``) by embedding the
    provided secret using the given key. The optional ``position``
    string can include method‑specific placement or strategy hints.

``read_secret(pdf, key) -> str``
    Recover and return the embedded secret from the given PDF using the
    provided key. Implementations should raise
    :class:`SecretNotFoundError` when no recognizable watermark is
    present and :class:`InvalidKeyError` when the key is incorrect.

Utilities
---------
This module also exposes :func:`load_pdf_bytes` and :func:`is_pdf_bytes`
which are convenience helpers many implementations will find useful.

"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import IO, ClassVar, TypeAlias

# ----------------------------
# Public type aliases & errors
# ----------------------------

PdfSource: TypeAlias = bytes | str | os.PathLike[str] | IO[bytes]
"""Accepted input type for a PDF document.

Implementations should *not* assume the input is a file path; always call
:func:`load_pdf_bytes` to normalize a :class:`PdfSource` into
``bytes`` before processing.
"""


class WatermarkingError(Exception):
    """Base class for all watermarking-related errors."""


class SecretNotFoundError(WatermarkingError):
    """Raised when a watermark/secret cannot be found in the PDF."""


class InvalidKeyError(WatermarkingError):
    """Raised when the provided key does not validate/decrypt correctly."""


# ----------------------------
# Helper functions
# ----------------------------

def load_pdf_bytes(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``.

    Parameters
    ----------
    src:
        The PDF input. Can be raw bytes, an open binary file handle,
        or a filesystem path (``str``/``PathLike``).

    Returns
    -------
    bytes
        The full contents of the PDF as a byte string.

    Raises
    ------
    FileNotFoundError
        If ``src`` is a path that does not exist.
    ValueError
        If the resolved bytes do not appear to be a PDF file.
    """
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        # Treat as a binary file-like (IO[bytes])
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError(
            "Unsupported PdfSource; expected bytes, path, or binary IO"
        )

    if not is_pdf_bytes(data):
        raise ValueError("Input does not look like a valid PDF (missing %PDF header)")
    return data


def is_pdf_bytes(data: bytes) -> bool:
    """Lightweight check that the data looks like a PDF file.

    This is intentionally permissive: it verifies the standard header
    magic (``%PDF-``). Trailers (``%%EOF``) can be absent in incremental
    updates, so we don't strictly require them here.
    """
    return data.startswith(b"%PDF-")


# ---------------------------------
# Abstract base class (the contract)
# ---------------------------------

class WatermarkingMethod(ABC):
    """Abstract base class for PDF watermarking algorithms.

    Subclasses define how secrets are embedded into and extracted from a
    PDF document. All I/O is performed in-memory; callers manage reading
    from and writing to files as needed.
    """

    #: Optional, human-friendly unique identifier for the method.
    #: Concrete implementations should override this with a short name
    #: (e.g., "toy-eof", "xmp-metadata", "object-stream").
    name: ClassVar[str] = "abstract"
    
    
    @staticmethod
    @abstractmethod
    def get_usage() -> str:
        """Return a a string containing a description of the expected usage.

        It's highly recommended to provide a description if custom position 
        is expected.

        Returns
        -------
        str
            Usage description.
        """
        raise NotImplementedError

    @abstractmethod
    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with an embedded watermark.

        Implementations *must* be deterministic given identical inputs
        to support reproducible pipelines and testing.

        Parameters
        ----------
        pdf:
            The source PDF (bytes, path, or binary file object).
        secret:
            The cleartext secret to embed. Implementations may apply
            authenticated encryption or integrity checks using ``key``.
        key:
            A string used to derive encryption/obfuscation material or
            as a password. The semantics are method-specific.
        position:
            Optional placement or strategy hint (method-specific). For
            example: a page index, object number, or named region.

        Returns
        -------
        bytes
            The complete, watermarked PDF as a byte string.

        Raises
        ------
        WatermarkingError
            On any failure to embed the watermark.
        ValueError
            If inputs are invalid (e.g., not a PDF or empty secret).
        """
        raise NotImplementedError
        
    @abstractmethod
    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        """Return whether the method is applicable on this specific method 

        Parameters
        ----------
        pdf:
            The source PDF (bytes, path, or binary file object).
        secret:
            The cleartext secret to embed. Implementations may apply
            authenticated encryption or integrity checks using ``key``.
        key:
            A string used to derive encryption/obfuscation material or
            as a password. The semantics are method-specific.
        position:
            Optional placement or strategy hint (method-specific). For
            example: a page index, object number, or named region.

        Returns
        -------
        bool
            If true, calling add_watermark should not return errors.

        Raises
        ------
        ValueError
            If inputs are invalid (e.g., not a PDF or empty secret).
        """
        raise NotImplementedError

    @abstractmethod
    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """Extract and return the embedded secret from ``pdf``.

        Parameters
        ----------
        pdf:
            The candidate PDF containing an embedded secret.
        key:
            The key required to validate/decrypt the watermark.

        Returns
        -------
        str
            The recovered secret.

        Raises
        ------
        SecretNotFoundError
            If no recognizable watermark is present in the PDF.
        InvalidKeyError
            If the provided key does not validate or decrypt correctly.
        WatermarkingError
            For other extraction errors.
        """
        raise NotImplementedError


__all__ = [
    "InvalidKeyError",
    "PdfSource",
    "SecretNotFoundError",
    "WatermarkingError",
    "WatermarkingMethod",
    "is_pdf_bytes",
    "load_pdf_bytes",
]

