# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp-icmp-shadow.

Cubre las funciones de ofuscación XOR+Base64, constantes del módulo,
fragmentación de mensajes y comportamiento del ShadowListener sin red.
"""

import base64

# El conftest.py ya insertó los mocks de Scapy y el path correcto.
# Re-importamos aquí para que el IDE / linters lo vean explícitamente.
import vamp_icmp_shadow as icmp_shadow

# ────────────────────────────────────────────────────────────────────────────
# Tests de _xor
# ────────────────────────────────────────────────────────────────────────────

class TestXOR:
    """Pruebas del cifrado XOR simétrico."""

    def test_xor_simetrico(self):
        """Aplicar XOR dos veces con la misma clave recupera los datos originales."""
        datos = b"Datos secretos de prueba"
        clave = "CLAVE_TEST"
        resultado = icmp_shadow._xor(icmp_shadow._xor(datos, clave), clave)
        assert resultado == datos

    def test_xor_produce_bytes_distintos(self):
        """El XOR transforma los datos; el resultado no es igual al texto original."""
        datos = b"hola"
        clave = "VAMP"
        resultado = icmp_shadow._xor(datos, clave)
        assert resultado != datos

    def test_xor_clave_se_repite_ciclicamente(self):
        """La clave se recicla; posiciones equivalentes mod len(clave) usan el mismo byte."""
        datos = b"AAAAAA"  # 6 bytes iguales
        clave = "AB"       # 2 bytes
        resultado = icmp_shadow._xor(datos, clave)
        # Con key=[A,B,A,B,A,B] → xor[0]==xor[2]==xor[4] y xor[1]==xor[3]==xor[5]
        assert resultado[0] == resultado[2] == resultado[4]
        assert resultado[1] == resultado[3] == resultado[5]

    def test_xor_datos_vacios(self):
        """XOR con datos vacíos devuelve bytes vacíos."""
        assert icmp_shadow._xor(b"", "clave") == b""

    def test_xor_resultado_es_bytes(self):
        """El tipo de retorno siempre es bytes."""
        resultado = icmp_shadow._xor(b"test", "k")
        assert isinstance(resultado, bytes)


# ────────────────────────────────────────────────────────────────────────────
# Tests de obfuscate
# ────────────────────────────────────────────────────────────────────────────

class TestObfuscate:
    """Pruebas de la función de ofuscación XOR+Base64."""

    def test_obfuscate_comienza_con_prefijo_magico(self, mensaje_corto, default_key):
        """El resultado siempre comienza con MAGIC_PREFIX."""
        resultado = icmp_shadow.obfuscate(mensaje_corto, default_key)
        assert resultado.startswith(icmp_shadow.MAGIC_PREFIX)

    def test_obfuscate_parte_base64_es_valida(self, mensaje_corto, default_key):
        """La parte tras el prefijo es Base64 decodificable."""
        resultado = icmp_shadow.obfuscate(mensaje_corto, default_key)
        parte_b64 = resultado[len(icmp_shadow.MAGIC_PREFIX):]
        # No debe lanzar excepción al decodificar
        decoded = base64.b64decode(parte_b64.encode("ascii"))
        assert isinstance(decoded, bytes)

    def test_obfuscate_oculta_texto_original(self, mensaje_corto, default_key):
        """El texto original no aparece en claro dentro del resultado."""
        resultado = icmp_shadow.obfuscate(mensaje_corto, default_key)
        assert mensaje_corto not in resultado

    def test_obfuscate_diferentes_claves_producen_resultados_distintos(self, mensaje_corto):
        """La misma entrada con claves distintas produce salidas distintas."""
        r1 = icmp_shadow.obfuscate(mensaje_corto, "CLAVE_A")
        r2 = icmp_shadow.obfuscate(mensaje_corto, "CLAVE_B")
        assert r1 != r2

    def test_obfuscate_retorna_cadena(self, mensaje_corto, default_key):
        """El tipo de retorno es str."""
        resultado = icmp_shadow.obfuscate(mensaje_corto, default_key)
        assert isinstance(resultado, str)


# ────────────────────────────────────────────────────────────────────────────
# Tests de deobfuscate
# ────────────────────────────────────────────────────────────────────────────

class TestDeobfuscate:
    """Pruebas de la función de desofuscación."""

    def test_deobfuscate_recupera_texto_original(self, mensaje_corto, default_key):
        """Roundtrip completo: obfuscate → deobfuscate recupera el mensaje."""
        ofuscado = icmp_shadow.obfuscate(mensaje_corto, default_key)
        recuperado = icmp_shadow.deobfuscate(ofuscado, default_key)
        assert recuperado == mensaje_corto

    def test_deobfuscate_sin_prefijo_devuelve_none(self, payload_sin_prefijo, default_key):
        """Un payload sin MAGIC_PREFIX retorna None."""
        resultado = icmp_shadow.deobfuscate(payload_sin_prefijo, default_key)
        assert resultado is None

    def test_deobfuscate_base64_invalido_devuelve_none(self, payload_invalido, default_key):
        """Payload con base64 inválido retorna None sin lanzar excepción."""
        resultado = icmp_shadow.deobfuscate(payload_invalido, default_key)
        assert resultado is None

    def test_deobfuscate_clave_incorrecta_no_lanza_excepcion(self, mensaje_corto, default_key, clave_incorrecta):
        """Con clave incorrecta no lanza excepción, pero el resultado es distinto."""
        ofuscado = icmp_shadow.obfuscate(mensaje_corto, default_key)
        resultado = icmp_shadow.deobfuscate(ofuscado, clave_incorrecta)
        # Puede decodificar bytes pero el texto resultante no coincide
        assert resultado != mensaje_corto

    def test_deobfuscate_cadena_vacia_con_prefijo(self, default_key):
        """Payload vacío con solo el prefijo mágico devuelve cadena vacía o None."""
        solo_prefijo = icmp_shadow.MAGIC_PREFIX
        resultado = icmp_shadow.deobfuscate(solo_prefijo, default_key)
        # Puede devolver "" o None — ambos son comportamientos aceptables
        assert resultado == "" or resultado is None

    def test_deobfuscate_preserva_unicode(self, default_key):
        """El roundtrip preserva caracteres Unicode (español, emojis básicos)."""
        mensaje_unicode = "Contraseña: café ñoño"
        ofuscado = icmp_shadow.obfuscate(mensaje_unicode, default_key)
        recuperado = icmp_shadow.deobfuscate(ofuscado, default_key)
        assert recuperado == mensaje_unicode


# ────────────────────────────────────────────────────────────────────────────
# Tests de constantes del módulo
# ────────────────────────────────────────────────────────────────────────────

class TestConstantes:
    """Pruebas de los valores de las constantes definidas en el módulo."""

    def test_magic_prefix_valor(self):
        """MAGIC_PREFIX es 'VSHDW:' exactamente."""
        assert icmp_shadow.MAGIC_PREFIX == "VSHDW:"

    def test_chunk_size_valor(self):
        """CHUNK_SIZE es 200 bytes por chunk ICMP."""
        assert icmp_shadow.CHUNK_SIZE == 200

    def test_default_key_valor(self):
        """DEFAULT_KEY contiene la clave de laboratorio 2026."""
        assert icmp_shadow.DEFAULT_KEY == "VAMP_KEY_2026"

    def test_version_presente(self):
        """VERSION está definida en el módulo."""
        assert hasattr(icmp_shadow, "VERSION")
        assert icmp_shadow.VERSION != ""

    def test_tool_name_presente(self):
        """TOOL_NAME está definido en el módulo."""
        assert icmp_shadow.TOOL_NAME == "vamp-icmp-shadow"


# ────────────────────────────────────────────────────────────────────────────
# Tests de fragmentación de mensajes
# ────────────────────────────────────────────────────────────────────────────

class TestFragmentacion:
    """Pruebas de la lógica de fragmentación en chunks ICMP."""

    def test_mensaje_corto_produce_un_chunk(self, mensaje_corto, default_key):
        """Un mensaje corto genera un único chunk al ofuscarse."""
        ofuscado = icmp_shadow.obfuscate(mensaje_corto, default_key)
        chunks = [
            ofuscado[i:i + icmp_shadow.CHUNK_SIZE]
            for i in range(0, len(ofuscado), icmp_shadow.CHUNK_SIZE)
        ]
        assert len(chunks) == 1

    def test_mensaje_largo_produce_multiples_chunks(self, mensaje_largo, default_key):
        """Un mensaje largo genera más de un chunk al superar CHUNK_SIZE."""
        ofuscado = icmp_shadow.obfuscate(mensaje_largo, default_key)
        chunks = [
            ofuscado[i:i + icmp_shadow.CHUNK_SIZE]
            for i in range(0, len(ofuscado), icmp_shadow.CHUNK_SIZE)
        ]
        assert len(chunks) > 1

    def test_todos_los_chunks_tienen_prefijo_magico(self, mensaje_corto, default_key):
        """Al menos el primer chunk comienza con el prefijo mágico."""
        ofuscado = icmp_shadow.obfuscate(mensaje_corto, default_key)
        assert ofuscado.startswith(icmp_shadow.MAGIC_PREFIX)


# ────────────────────────────────────────────────────────────────────────────
# Tests de ShadowListener
# ────────────────────────────────────────────────────────────────────────────

class TestShadowListener:
    """Pruebas de la inicialización del receptor ICMP Shadow."""

    def test_init_buffer_vacio(self, listener):
        """El buffer de recepción comienza vacío."""
        assert listener._buffer == {}

    def test_init_contador_cero(self, listener):
        """El contador de paquetes capturados comienza en cero."""
        assert listener._count == 0

    def test_init_almacena_clave(self, listener, default_key):
        """La clave se almacena en la instancia."""
        assert listener.key == default_key

    def test_init_verbose_false(self, listener):
        """El modo verbose está desactivado por defecto en el fixture."""
        assert listener.verbose is False

    def test_init_verbose_true(self, listener_verbose):
        """El modo verbose puede activarse en la instancia."""
        assert listener_verbose.verbose is True
