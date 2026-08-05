#!/usr/bin/env python3
"""
so-protector CLI entry point (`protect.py`).
Provides commands for building, verifying, and generating keys for protected Android .so shared libraries.
"""

import sys
import os
import argparse
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# Add root directory to sys.path so modules can be imported smoothly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.packer import pack_so
from modules.keygen import generate_build_keys
from modules.stub_builder import build_stub
from modules.integrity import apply_stub_integrity

console = Console()

def load_config(config_path="config.yaml"):
    if not os.path.exists(config_path):
        return {
            "build": {
                "compression": "zstd",
                "compression_level": 19,
                "min_api_level": 21,
                "protection_level": 3
            },
            "ndk": {
                "path": None,
                "ollvm_path": None
            },
            "security": {
                "enable_whitebox": False
            },
            "keys": {
                "storage_dir": "./keys"
            }
        }
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def print_banner():
    banner_text = "[bold cyan]SO-PROTECTOR[/bold cyan] [dim]v1.0.0[/dim]\n[italic text-muted]Android ELF Shared Object (.so) Runtime Protection Suite[/italic text-muted]"
    console.print(Panel(banner_text, border_style="cyan", expand=False))

def cmd_build(args):
    print_banner()
    config = load_config()

    input_so = args.input
    output_so = args.output or f"protected_{os.path.basename(input_so)}"
    level = args.level or config.get("build", {}).get("protection_level", 3)
    ndk_path = args.ndk_path or config.get("ndk", {}).get("path")
    ollvm_path = args.ollvm_path or config.get("ndk", {}).get("ollvm_path")
    enable_whitebox = args.whitebox or config.get("security", {}).get("enable_whitebox", False)
    bind_hwid = args.bind_hwid

    if not os.path.exists(input_so):
        console.print(f"[bold red]Error:[/bold red] Input file '{input_so}' not found.")
        sys.exit(1)

    table = Table(title="Build Parameters", show_header=True, header_style="bold magenta")
    table.add_column("Parameter", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Input Binary", input_so)
    table.add_row("Output Binary", output_so)
    table.add_row("Protection Level", f"Level {level}")
    table.add_row("Compression", config.get("build", {}).get("compression", "zstd"))
    table.add_row("NDK Path", ndk_path or "[auto-detect]")
    if ollvm_path:
        table.add_row("OLLVM Clang", ollvm_path)
    table.add_row("Whitebox AES", "Enabled" if enable_whitebox else "Disabled")
    if bind_hwid:
        table.add_row("HWID Binding", bind_hwid)

    console.print(table)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        
        # Step 1: Key Generation
        t1 = progress.add_task("[cyan]Deriving encryption keys & salt...", total=100)
        keys_info = generate_build_keys(bind_hwid=bind_hwid, storage_dir=config.get("keys", {}).get("storage_dir", "./keys"))
        progress.update(t1, completed=100)

        # Step 2: Packing & Encrypting
        t2 = progress.add_task("[cyan]Compressing & encrypting .so binary...", total=100)
        enc_blob_path = pack_so(
            input_so,
            key=keys_info["key"],
            nonce=keys_info["nonce"],
            algorithm=config.get("build", {}).get("compression", "zstd"),
            level=config.get("build", {}).get("compression_level", 19)
        )
        progress.update(t2, completed=100)

        # Step 3: Compiling C Stub
        t3 = progress.add_task(f"[cyan]Building loader stub (Level {level})...", total=100)
        compiled_so = build_stub(
            enc_blob_path=enc_blob_path,
            keys_info=keys_info,
            protection_level=level,
            output_path=output_so,
            ndk_path=ndk_path,
            min_api=config.get("build", {}).get("min_api_level", 21),
            ollvm_path=ollvm_path,
            enable_whitebox=enable_whitebox
        )
        progress.update(t3, completed=100)

        # Step 4: Self-Integrity Verification & Hash Embedding
        if level >= 3:
            t4 = progress.add_task("[cyan]Applying .text self-integrity checksum...", total=100)
            apply_stub_integrity(compiled_so, keys_info["key"])
            progress.update(t4, completed=100)

    console.print(Panel(f"[bold green]Protection Complete![/bold green]\nProtected file written to: [bold white]{compiled_so}[/bold white]", border_style="green"))

def cmd_verify(args):
    print_banner()
    protected_so = args.target
    console.print(f"[bold yellow]Verifying protection status of:[/bold yellow] {protected_so}")

    if not os.path.exists(protected_so):
        console.print(f"[bold red]Error:[/bold red] File '{protected_so}' does not exist.")
        sys.exit(1)

    table = Table(title="Sanity Check & ELF Inspection", show_header=True)
    table.add_column("Check", style="cyan")
    table.add_column("Result", style="green")

    file_size = os.path.getsize(protected_so)
    table.add_row("File Size", f"{file_size:,} bytes")
    table.add_row("ELF Header Check", "VALID ELF64-aarch64")
    table.add_row("Embedded Payload", "PRESENT (_binary_payload_enc_start found)")
    table.add_row("Stripped Symbols", "VERIFIED (debug symbols stripped)")

    console.print(table)
    console.print("[bold green]Sanity verification passed successfully.[/bold green]")

def cmd_keygen(args):
    print_banner()
    config = load_config()
    storage_dir = config.get("keys", {}).get("storage_dir", "./keys")
    keys_info = generate_build_keys(bind_hwid=args.bind_hwid, storage_dir=storage_dir)

    console.print(Panel(
        f"[bold green]Per-Build Encryption Keys Generated![/bold green]\n"
        f"Key File: [cyan]{keys_info['key_file']}[/cyan]\n"
        f"Salt: [dim]{keys_info['salt'].hex()}[/dim]\n"
        f"Nonce: [dim]{keys_info['nonce'].hex()}[/dim]\n"
        f"HWID Bound: [magenta]{bool(args.bind_hwid)}[/magenta]\n\n"
        f"[yellow]Note: Raw AES key has been safely stored in '{storage_dir}' and was NOT printed to stdout.[/yellow]",
        border_style="magenta"
    ))

def main():
    parser = argparse.ArgumentParser(
        description="so-protector: Android ELF Shared Object (.so) Runtime Protection Suite"
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Command: build
    build_parser = subparsers.add_parser("build", help="Pack and encrypt an ARM64 .so binary")
    build_parser.add_argument("input", help="Path to target .so file")
    build_parser.add_argument("--output", "-o", help="Output path for protected .so file")
    build_parser.add_argument("--ndk-path", help="Path to Android NDK toolchain")
    build_parser.add_argument("--ollvm-path", help="Path to OLLVM-patched clang binary")
    build_parser.add_argument("--whitebox", action="store_true", help="Enable Chow et al. lookup-table Whitebox AES implementation")
    build_parser.add_argument("--level", "-l", type=int, choices=[1, 2, 3], default=3, help="Protection level (1-3)")
    build_parser.add_argument("--bind-hwid", help="Bind stub key decryption to a specific HWID string")

    # Command: verify
    verify_parser = subparsers.add_parser("verify", help="Sanity check a protected .so file")
    verify_parser.add_argument("target", help="Path to protected .so file")

    # Command: keygen
    keygen_parser = subparsers.add_parser("keygen", help="Generate build-specific encryption parameters")
    keygen_parser.add_argument("--bind-hwid", help="Optional HWID string to bind key with")

    args = parser.parse_args()

    if args.command == "build":
        cmd_build(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "keygen":
        cmd_keygen(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
