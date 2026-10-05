# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp-icmp-shadow.

Verifica el pipeline completo de ofuscación → fragmentación → reconstrucción
y el comportamiento del receptor ante paquetes ICMP simulados.
No realiza ninguna llamada de red real ni requiere privilegios root.
"""

import sys
from unittest.mock import MagicMock, patch

import vamp_icmp_shadow as icmp_shadow

# ────────────────────────────────────────────────────────────────────────────
# Pipeline completo de roundtrip
# ────────────────────────────────────────────────────────────────────────────

class TestRoundtripCompleto:
    """Pruebas del pipeline encode→decode sin red."""

    def test_roundtrip_xor_base64_mensaje_corto(self, mensaje_corto, default_key):
        """Roundtrip completo con mensaje corto y clave por defecto."""
        encoded = icmp_shadow.obfuscate(mensaje_corto, default_key)
        decoded = icmp_shadow.deobfuscate(encoded, default_key)
        assert decoded == mensaje_corto

    def test_roundtrip_xor_base64_mensaje_largo(self, mensaje_largo, default_key):
        """Roundtrip completo con mensaje largo (múltiples chunks)."""
        encoded = icmp_shadow.obfuscate(mensaje_largo, default_key)
        decoded = icmp_shadow.deobfuscate(encoded, default_key)
        assert decoded == mensaje_largo

    def test_roundtrip_con_clave_personalizada(self, mensaje_corto, custom_key):
        """Roundtrip con una clave XOR personalizada distinta de la por defecto."""
        encoded = icmp_shadow.obfuscate(mensaje_corto, custom_key)
        decoded = icmp_shadow.deobfuscate(encoded, custom_key)
        assert decoded == mensaje_corto

    def test_roundtrip_datos_binarios_representables(self, default_key):
        """Roundtrip con un mensaje que contiene caracteres especiales ASCII."""
        mensaje = "EXFIL:password=P@$$w0rd!#%&<>secret"
        encoded = icmp_shadow.obfuscate(mensaje, default_key)
        decoded = icmp_shadow.deobfuscate(encoded, default_key)
        assert decoded == mensaje

    def test_roundtrip_lineas_multiples(self, default_key):
        """Roundtrip con un mensaje de múltiples líneas (saltos de línea)."""
        mensaje = "Línea 1\nLínea 2\nLínea 3\n"
        encoded = icmp_shadow.obfuscate(mensaje, default_key)
        decoded = icmp_shadow.deobfuscate(encoded, default_key)
        assert decoded == mensaje


# ────────────────────────────────────────────────────────────────────────────
# Fragmentación de mensajes
# ────────────────────────────────────────────────────────────────────────────

class TestFragmentacionIntegracion:
    """Pruebas de la lógica de fragmentación en el flujo de envío."""

    def test_numero_chunks_proporcional_al_tamano(self, default_key):
        """El número de chunks crece proporcionalmente al tamaño del mensaje."""
        # 500 bytes → Base64 ~668 chars + prefijo "VSHDW:" → 674 chars → 4 chunks de 200
        mensaje_500 = "B" * 500
        ofuscado = icmp_shadow.obfuscate(mensaje_500, default_key)
        chunks = [
            ofuscado[i:i + icmp_shadow.CHUNK_SIZE]
            for i in range(0, len(ofuscado), icmp_shadow.CHUNK_SIZE)
        ]
        assert len(chunks) >= 4

    def test_concatenacion_chunks_permite_reconstruccion(self, mensaje_largo, default_key):
        """Unir todos los chunks produce el payload original completo."""
        ofuscado = icmp_shadow.obfuscate(mensaje_largo, default_key)
        chunks = [
            ofuscado[i:i + icmp_shadow.CHUNK_SIZE]
            for i in range(0, len(ofuscado), icmp_shadow.CHUNK_SIZE)
        ]
        reconstruido = "".join(chunks)
        assert reconstruido == ofuscado

    def test_todos_los_chunks_ascii_puro(self, mensaje_largo, default_key):
        """Todos los chunks son cadenas ASCII puras (seguras para el campo Raw ICMP)."""
        ofuscado = icmp_shadow.obfuscate(mensaje_largo, default_key)
        chunks = [
            ofuscado[i:i + icmp_shadow.CHUNK_SIZE]
            for i in range(0, len(ofuscado), icmp_shadow.CHUNK_SIZE)
        ]
        for chunk in chunks:
            chunk.encode("ascii")  # no debe lanzar excepción


# ────────────────────────────────────────────────────────────────────────────
# Integración con send_data (Scapy mockeado)
# ────────────────────────────────────────────────────────────────────────────

class TestSendDataIntegracion:
    """Pruebas del emisor con Scapy completamente mockeado."""

    def test_send_data_invoca_send_una_vez_por_chunk(self, default_key):
        """send_data llama a send() una vez por cada chunk del mensaje."""
        # Acceder al mock de send desde sys.modules (puesto por conftest.py)
        mock_send = sys.modules["scapy.all"].send
        mock_send.reset_mock()

        mensaje = "Mensaje breve"
        ofuscado = icmp_shadow.obfuscate(mensaje, default_key)
        n_chunks_esperados = len(range(0, len(ofuscado), icmp_shadow.CHUNK_SIZE))

        with patch("vamp_icmp_shadow.time.sleep"):  # suprimir la pausa de 50ms
            icmp_shadow.send_data(
                target="127.0.0.1",
                message=mensaje,
                key=default_key,
                verbose=False,
            )

        assert mock_send.call_count == n_chunks_esperados

    def test_send_data_mensaje_largo_multiples_llamadas(self, mensaje_largo, default_key):
        """send_data con mensaje largo realiza múltiples llamadas a send()."""
        mock_send = sys.modules["scapy.all"].send
        mock_send.reset_mock()

        with patch("vamp_icmp_shadow.time.sleep"):
            icmp_shadow.send_data(
                target="192.168.1.1",
                message=mensaje_largo,
                key=default_key,
                verbose=False,
            )

        assert mock_send.call_count > 1


# ────────────────────────────────────────────────────────────────────────────
# ShadowListener — procesamiento de paquetes
# ────────────────────────────────────────────────────────────────────────────

class TestShadowListenerIntegracion:
    """Pruebas del receptor ante paquetes ICMP simulados."""

    def _crear_paquete_shadow(self, mensaje: str, key: str, seq: int = 1, src: str = "10.0.0.1"):
        """
        Crea un mock de paquete Scapy con payload Shadow válido.
        Simula las capas IP, ICMP y Raw usando MagicMock.
        """
        # Obtener los constructores mockeados del módulo de Scapy
        IP_cls = sys.modules["scapy.all"].IP
        ICMP_cls = sys.modules["scapy.all"].ICMP
        Raw_cls = sys.modules["scapy.all"].Raw

        pkt = MagicMock()

        # Simular haslayer: devuelve True para ICMP y Raw
        def haslayer_side(capa):
            return capa in (ICMP_cls, Raw_cls)

        pkt.haslayer.side_effect = haslayer_side

        # Simular __getitem__ para acceder a las capas
        capa_icmp = MagicMock()
        capa_icmp.type = 8
        capa_icmp.seq = seq

        capa_raw = MagicMock()
        capa_raw.load = icmp_shadow.obfuscate(mensaje, key).encode("ascii")

        capa_ip = MagicMock()
        capa_ip.src = src

        def getitem_side(capa):
            if capa is ICMP_cls:
                return capa_icmp
            elif capa is Raw_cls:
                return capa_raw
            elif capa is IP_cls:
                return capa_ip
            return MagicMock()

        pkt.__getitem__ = MagicMock(side_effect=getitem_side)
        return pkt

    def test_process_paquete_shadow_valido_incrementa_count(self, listener, mensaje_corto, default_key):
        """El listener incrementa _count al procesar un paquete Shadow válido."""
        pkt = self._crear_paquete_shadow(mensaje_corto, default_key)
        listener.process(pkt)
        assert listener._count == 1

    def test_process_paquete_shadow_acumula_en_buffer(self, listener, mensaje_corto, default_key):
        """El listener acumula chunks de la misma IP en su buffer interno."""
        pkt = self._crear_paquete_shadow(mensaje_corto, default_key, src="10.10.10.10")
        listener.process(pkt)
        assert "10.10.10.10" in listener._buffer
        assert len(listener._buffer["10.10.10.10"]) == 1

    def test_process_paquete_sin_raw_ignorado(self, listener):
        """Paquetes sin capa Raw son ignorados silenciosamente."""
        ICMP_cls = sys.modules["scapy.all"].ICMP
        sys.modules["scapy.all"].Raw

        pkt = MagicMock()
        pkt.haslayer.side_effect = lambda c: c is ICMP_cls  # solo tiene ICMP, no Raw
        listener.process(pkt)
        assert listener._count == 0

    def test_process_paquete_icmp_tipo_0_ignorado(self, listener):
        """Paquetes ICMP Echo Reply (type=0) son ignorados (solo procesa type=8)."""
        ICMP_cls = sys.modules["scapy.all"].ICMP
        Raw_cls = sys.modules["scapy.all"].Raw

        pkt = MagicMock()
        pkt.haslayer.side_effect = lambda c: c in (ICMP_cls, Raw_cls)
        capa_icmp = MagicMock()
        capa_icmp.type = 0  # Echo Reply
        pkt.__getitem__ = MagicMock(return_value=capa_icmp)
        listener.process(pkt)
        assert listener._count == 0

    def test_process_payload_sin_prefijo_ignorado(self, listener, default_key):
        """Paquetes con payload sin MAGIC_PREFIX son ignorados."""
        ICMP_cls = sys.modules["scapy.all"].ICMP
        Raw_cls = sys.modules["scapy.all"].Raw
        sys.modules["scapy.all"].IP

        pkt = MagicMock()
        pkt.haslayer.side_effect = lambda c: c in (ICMP_cls, Raw_cls)
        capa_icmp = MagicMock()
        capa_icmp.type = 8
        capa_icmp.seq = 1
        capa_raw = MagicMock()
        capa_raw.load = b"SGVsbG8gV29ybGQ="  # base64 sin prefijo VSHDW:
        pkt.__getitem__ = MagicMock(side_effect=lambda c: (
            capa_icmp if c is ICMP_cls else (capa_raw if c is Raw_cls else MagicMock())
        ))
        listener.process(pkt)
        assert listener._count == 0
