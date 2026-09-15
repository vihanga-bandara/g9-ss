"""watermarking_cli.py

Command-line interface for the PDF watermarking toolkit.

Usage examples
--------------

List available methods:
    python -m watermarking_cli methods

Explore a PDF and write a JSON node tree:
    python -m watermarking_cli explore input.pdf --out tree.json

Embed a secret using the default method (toy-eof) and write a new PDF:
    python -m watermarking_cli embed input.pdf output.pdf --key-prompt --secret "hello"

Extract a secret:
    python -m watermarking_cli extract input.watermarked.pdf --key-prompt

Exit codes
----------
0   success
2   invalid usage / bad input
3   secret not found
4   invalid key / authentication failed
5   other watermarking error
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Iterable

from watermarking_method import InvalidKeyError, SecretNotFoundError, WatermarkingError
from watermarking_utils import (
    METHODS,
    apply_watermark,
    explore_pdf,
    is_watermarking_applicable,
    read_watermark,
)

__version__ = "0.1.0"

# --------------------
# Helpers
# --------------------

def _read_text_from_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _read_text_from_stdin() -> str:
    data = sys.stdin.read()
    if not data:
        raise ValueError("No data received on stdin")
    return data


def _resolve_secret(args: argparse.Namespace) -> str:
    if args.secret is not None:
        return args.secret
    if args.secret_file is not None:
        return _read_text_from_file(args.secret_file)
    if args.secret_stdin:
        return _read_text_from_stdin()
    # Interactive fallback
    return getpass.getpass("Secret: ")


def _resolve_key(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("Key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("Key: ")


# --------------------
# Subcommand handlers
# --------------------

def cmd_methods(_args: argparse.Namespace) -> int:
    for name in sorted(METHODS):
        print(name)
    return 0


def cmd_explore(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def cmd_embed(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


# --------------------
# Argument parser
# --------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Entrypoint
# --------------------

def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())

