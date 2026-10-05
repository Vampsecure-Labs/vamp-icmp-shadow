# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para vamp-icmp-shadow.

Mockea Scapy antes de importar el módulo objetivo para evitar sys.exit(1)
cuando Scapy no está instalado o no se tienen privilegios root.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ── Mock de Scapy ANTES de cualquier importación del módulo ─────────────────
# El módulo llama a sys.exit(1) si Scapy no está disponible.
# Insertamos los mocks en sys.modules para interceptar el import.
_scapy_mock = MagicMock()
_scapy_mock.IP = MagicMock(name="IP")
_scapy_mock.ICMP = MagicMock(name="ICMP")
_scapy_mock.Raw = MagicMock(name="Raw")
_scapy_mock.send = MagicMock(name="send")
_scapy_mock.sniff = MagicMock(name="sniff")
sys.modules.setdefault("scapy", _scapy_mock)
sys.modules.setdefault("scapy.all", _scapy_mock)

# Añadir el directorio raíz de la herramienta al path de importación
_TOOL_DIR = Path(__file__).resolve().parent.parent
if str(_TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOL_DIR))

import vamp_icmp_shadow as icmp_shadow

# ── Fixtures de claves ───────────────────────────────────────────────────────

@pytest.fixture
def default_key():
    """Clave XOR por defecto definida en el módulo."""
    return icmp_shadow.DEFAULT_KEY


@pytest.fixture
def custom_key():
    """Clave XOR personalizada para verificar comportamiento con clave distinta."""
    return "CLAVE_ALTERNA_2026"


@pytest.fixture
def clave_incorrecta():
    """Clave incorrecta para verificar que la decodificación falla correctamente."""
    return "CLAVE_ERRONEA_XYZ"


# ── Fixtures de mensajes ─────────────────────────────────────────────────────

@pytest.fixture
def mensaje_corto():
    """Mensaje de prueba más corto que un solo chunk ICMP."""
    return "Mensaje de prueba para canal encubierto ICMP"


@pytest.fixture
def mensaje_largo():
    """Mensaje largo que genera múltiples chunks al ofuscarse."""
    # Al codificar en base64, el texto crece ~4/3; con 600 bytes texto
    # el base64 supera 800 caracteres, lo que requiere 5 chunks de 200.
    return "DATO_EXFILTRADO:" + "X" * 600


@pytest.fixture
def payload_sin_prefijo():
    """Payload ICMP sin el prefijo mágico de Shadow."""
    return "SGVsbG8gV29ybGQ="  # base64 de "Hello World" sin VSHDW:


@pytest.fixture
def payload_invalido():
    """Payload con prefijo correcto pero contenido base64 inválido."""
    return icmp_shadow.MAGIC_PREFIX + "!!!NO_ES_BASE64!!!"


# ── Fixture de ShadowListener ────────────────────────────────────────────────

@pytest.fixture
def listener(default_key):
    """Instancia fresca de ShadowListener para cada test."""
    return icmp_shadow.ShadowListener(key=default_key, verbose=False)


@pytest.fixture
def listener_verbose(default_key):
    """Instancia de ShadowListener en modo verbose."""
    return icmp_shadow.ShadowListener(key=default_key, verbose=True)


# ── Helpers de acceso a los constructores Scapy mockeados ────────────────────

@pytest.fixture
def scapy_mocks():
    """Devuelve el mock de scapy.all y sus constructores (IP, ICMP, Raw, send, sniff)."""
    mod = sys.modules["scapy.all"]
    return mod
