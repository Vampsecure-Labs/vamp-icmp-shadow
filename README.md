<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-icmp-shadow</h1>
<p align="center">
  <strong>Covert ICMP data channel for Red/Blue Team detection validation and IDS/IPS rule testing</strong><br>
  <em>VampSecure Labs · Security Research Division</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/license-research%20only-red?style=flat-square">
  <img src="https://img.shields.io/badge/VampSecure-Labs-8B0000?style=flat-square">
  <img src="https://github.com/Vampsecure-Labs/vamp-icmp-shadow/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

### Overview

`vamp-icmp-shadow` implements a covert data channel over ICMP for use in authorized Red/Blue Team lab environments. It demonstrates that the payload field of ICMP Echo Request packets can be used as a data exfiltration vector, bypassing network controls that filter only by protocol or port number without performing deep packet inspection on ICMP content.

The tool's primary purpose is **defensive**: validating that IDS/IPS rules (Snort, Suricata) correctly detect non-standard ICMP payloads, training Blue Team analysts to recognize the traffic pattern, and documenting the attack vector in network security audit reports. It must not be used outside of self-owned lab environments or without explicit written authorization.

Data is obfuscated via XOR with a shared key, encoded in Base64, prefixed with a magic marker (`VSHDW:`), and split into fixed-size chunks transmitted as individual ICMP Echo Request packets. The receiver side reassembles and decodes the stream.

### Features

- **`send` mode** — XOR-encrypts a message with the configured key, Base64-encodes it, fragments it into 200-byte chunks, and sends each chunk as an ICMP Echo Request (type=8) with sequential sequence numbers
- **`listen` mode** — captures ICMP Echo Request packets via Scapy BPF filter `icmp`, verifies the `VSHDW:` magic prefix, decodes Base64, applies XOR to recover plaintext, and displays captured messages in Rich panels with source IP and sequence number
- **XOR + Base64 obfuscation** — symmetric cipher (XOR key repeats cyclically); the same key decrypts: `XOR(XOR(data, key), key) = data`
- **Configurable key** via `--key` parameter or `--key-file` (first line of file) — default key is `VAMP_KEY_2026`
- **Magic-prefix filtering** — the receiver silently ignores all ICMP traffic that does not carry the `VSHDW:` prefix, making it quiet in mixed-traffic environments
- **Verbose mode** (`-v`) shows all ICMP packets received including those without the magic prefix, useful for debugging IDS rule placement
- **Chunk-based fragmentation** — messages longer than 200 obfuscated bytes are automatically split; the receiver accumulates chunks per source IP ordered by ICMP sequence number
- **Root privilege enforcement** — exits with an error if not run as root, as raw packet capture requires `CAP_NET_RAW`
- Rich console output: sender displays a per-packet table with payload preview, byte count, and status; receiver shows a panel per decoded message

### Requirements

```
pip install -r requirements.txt
```

| Package | Version |
|---------|---------|
| `scapy` | >= 2.5.0 |
| `rich`  | >= 13.7.0 |

Standard library: `argparse`, `base64`, `os`, `sys`, `time`, `datetime`, `pathlib`.

### Installation

```bash
git clone https://github.com/belky-me/vamp-icmp-shadow.git
cd vamp-icmp-shadow
pip install -r requirements.txt
```

Requires root or `CAP_NET_RAW` capability for both send and listen modes.

### Usage

```bash
python vamp_icmp_shadow.py --help
```

Two subcommands are available: `send` and `listen`.

```
usage: vamp-icmp-shadow {send,listen} ...

subcommands:
  send      Send a message via the ICMP Shadow channel
  listen    Listen for incoming ICMP Shadow channel traffic
```

### Examples

**Send a short message to a lab target (default key):**
```bash
sudo python vamp_icmp_shadow.py send -t 192.168.1.10 -d "shadow test"
```

**Send a message with a custom XOR key:**
```bash
sudo python vamp_icmp_shadow.py send -t 192.168.1.10 -d "exfil payload" -k "MY_SECRET_KEY"
```

**Send using a key loaded from a file:**
```bash
sudo python vamp_icmp_shadow.py send -t 192.168.1.10 -d "test" --key-file /etc/lab/icmp.key
```

**Send with verbose output (shows per-packet errors and status):**
```bash
sudo python vamp_icmp_shadow.py send -t 10.0.0.5 -d "blue team test" -v
```

**Listen on interface eth0 for incoming Shadow channel traffic:**
```bash
sudo python vamp_icmp_shadow.py listen -i eth0
```

**Listen with a custom key and verbose mode (shows non-Shadow ICMP too):**
```bash
sudo python vamp_icmp_shadow.py listen -i eth0 -k "MY_SECRET_KEY" -v
```

**Listen using a key file:**
```bash
sudo python vamp_icmp_shadow.py listen -i eth0 --key-file /etc/lab/icmp.key
```

### Protocol Overview

```
Sender:
  plaintext → XOR(key) → Base64 → "VSHDW:" + B64_CHUNK
  Each chunk → ICMP Echo Request (type=8, seq=N, payload=VSHDW:...)

Receiver:
  ICMP Echo Request captured → check for "VSHDW:" prefix
  → Base64 decode → XOR(key) → plaintext
  → display with source IP and sequence number
```

Chunk size: 200 bytes of the obfuscated Base64 string per packet.  
Inter-packet delay: 50 ms to avoid overwhelming the network stack.

### Blue Team Detection Notes

This tool is designed to make its own traffic detectable. Example Suricata signature that fires on the `VSHDW:` magic prefix in ICMP payloads:

```
alert icmp any any -> any any (msg:"VampSecure ICMP Shadow channel"; \
  content:"VSHDW:"; itype:8; sid:9000001; rev:1;)
```

Use this tool to verify that your IDS signature correctly triggers before writing it into the production ruleset.

### Sample Output

**Sender side** (sending a message to 10.0.0.20):

```
$ sudo python vamp_icmp_shadow.py send -t 10.0.0.20 -d "exfil test" -k "LAB_KEY_2026"
╔══════════════════════════════════════════════════════════╗
║           vamp-icmp-shadow — SEND MODE                   ║
║  Target: 10.0.0.20   Key: LAB_KEY_2026                   ║
╚══════════════════════════════════════════════════════════╝
┌──────────────────────────────────────────────────────────────────────┐
│  Seq   Payload preview                        Bytes    Status        │
├──────────────────────────────────────────────────────────────────────┤
│  001   VSHDW:ZXhmaWwgdGVzdA==                  24 B    ✓ sent        │
└──────────────────────────────────────────────────────────────────────┘
[✓] 1 packet(s) transmitted — message delivered
```

**Listener side** (capturing the channel on eth0):

```
$ sudo python vamp_icmp_shadow.py listen -i eth0 -k "LAB_KEY_2026"
╔══════════════════════════════════════════════════════════╗
║          vamp-icmp-shadow — LISTEN MODE                  ║
║  Interface: eth0   Key: LAB_KEY_2026                     ║
╚══════════════════════════════════════════════════════════╝
[*] Sniffing ICMP traffic on eth0 ...

╭─── Shadow message received ──────────────────────────────────────────╮
│  Source:   10.0.0.5                                                  │
│  Seq:      001                                                       │
│  Message:  exfil test                                                │
╰──────────────────────────────────────────────────────────────────────╯
```

> Suricata rule `sid:9000001` (see Blue Team Detection Notes) fires on the `VSHDW:` prefix visible in the packet capture.

---

### Why vamp-icmp-shadow vs. hping3 · Scapy manual · nping

| Feature | vamp-icmp-shadow | hping3 | Scapy manual | nping |
|---------|:---:|:---:|:---:|:---:|
| XOR+Base64 obfuscation layer | ✅ | ❌ | ❌ | ❌ |
| Built-in `listen` / decode mode | ✅ | ❌ | ❌ | ❌ |
| Magic-prefix filtering (ignores unrelated ICMP) | ✅ | ❌ | ❌ | ❌ |
| Chunk reassembly across multiple packets | ✅ | ❌ | ❌ | ❌ |
| Rich colored output for lab sessions | ✅ | ❌ | ❌ | ❌ |
| Key file support (`--key-file`) | ✅ | ❌ | ❌ | ❌ |
| Built-in Suricata detection example | ✅ | ❌ | ❌ | ❌ |
| Designed for IDS rule validation workflows | ✅ | ⚠️ indirect | ❌ | ⚠️ indirect |

- **hping3** can craft raw ICMP packets and set payloads manually, but provides no receive/decode side and no obfuscation; it tests connectivity and timing, not covert channel detection.
- **Scapy** is a powerful library that can replicate this tool's behavior, but requires writing multi-page scripts per test scenario; vamp-icmp-shadow is purpose-built, reproducible, and ready to run.
- **nping** (Nmap project) supports ICMP echo modes for performance testing but has no payload obfuscation or listener, making it unsuitable for IDS validation scenarios.
- vamp-icmp-shadow ships with a **matching Suricata signature** and is designed so Blue Team analysts can run sender and listener side-by-side in a lab, verify detection, and document the result in a single session.

---

### Research Context & Defensive Use

This tool exists for **IDS/IPS rule validation** and Red/Blue Team lab exercises. The table below maps each capability to its defensive research application.

| Capability | Defensive research application | Reference |
|------------|-------------------------------|-----------|
| ICMP payload channel (`send`) | Prove that ICMP data exfiltration is possible in permissive network environments | MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol |
| XOR obfuscation layer | Test whether IDS rules detect obfuscated payloads, not just plaintext strings | Snort/Suricata `content` + `pcre` operator coverage |
| Magic-prefix marker (`VSHDW:`) | Generate a known, deterministic IOC for rule creation and signature testing | Suricata `content` match (`itype:8`) |
| Chunk fragmentation across seq numbers | Validate that IDS reassembles ICMP streams before applying content rules | Suricata stream reassembly configuration |
| Custom key (`--key`, `--key-file`) | Simulate per-engagement key rotation; verify key changes do not break IDS coverage | Operational security simulation |
| Verbose mode on listener (`-v`) | Analyze all ICMP traffic in the capture window to locate false negatives | Blue Team traffic analysis workflow |
| `listen` decode mode | Confirm that the Blue Team can recover plaintext from captured ICMP traffic | IR evidence collection simulation |
| Root / `CAP_NET_RAW` enforcement | Ensures the tool only runs with appropriate privileges — avoids silent failures | Lab access control verification |
| Inter-packet 50 ms delay | Prevents overwhelming the network stack; provides reproducible timing for PCAP replay | IDS replay and regression testing |

---

### Part of VampSecure Labs Toolkit

This tool is part of the **VampSecure Labs Security Toolkit** — a collection of research-grade security tools for authorized penetration testing and red/blue team exercises.

- Full toolkit: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

### Version History

| Version | Main changes |
|---------|-------------|
| v1.1 | Bilingual README (EN/ES) |
| v1.0 | Initial release — ICMP covert channel, XOR+Base64 obfuscation, send/listen modes, Suricata detection example |

---

© VampSecure Studios — VampSecure Labs Security Research Division  
For authorized security testing only.

---
---

<a name="español"></a>
## 🇪🇸 Español

### Descripción general

`vamp-icmp-shadow` implementa un canal de datos encubierto sobre ICMP para su uso en entornos de laboratorio Red/Blue Team autorizados. Demuestra que el campo payload de los paquetes ICMP Echo Request puede usarse como vector de exfiltración de datos, eludiendo los controles de red que filtran solo por protocolo o número de puerto sin realizar inspección profunda de paquetes en el contenido ICMP.

El propósito principal de la herramienta es **defensivo**: validar que las reglas IDS/IPS (Snort, Suricata) detecten correctamente payloads ICMP no estándar, entrenar a los analistas del Blue Team para reconocer el patrón de tráfico y documentar el vector de ataque en informes de auditoría de seguridad de red. No debe usarse fuera de entornos de laboratorio de propiedad propia o sin autorización escrita explícita.

Los datos se ofuscan mediante XOR con una clave compartida, se codifican en Base64, se prefijan con un marcador mágico (`VSHDW:`) y se dividen en chunks de tamaño fijo transmitidos como paquetes ICMP Echo Request individuales. El lado receptor reensambla y decodifica el stream.

### Características

- **Modo `send`** — Cifra un mensaje con XOR con la clave configurada, lo codifica en Base64, lo fragmenta en chunks de 200 bytes y envía cada chunk como un ICMP Echo Request (type=8) con números de secuencia secuenciales
- **Modo `listen`** — Captura paquetes ICMP Echo Request mediante el filtro BPF de Scapy `icmp`, verifica el prefijo mágico `VSHDW:`, decodifica Base64, aplica XOR para recuperar texto plano y muestra los mensajes capturados en paneles Rich con IP de origen y número de secuencia
- **Ofuscación XOR + Base64** — Cifrado simétrico (la clave XOR se repite cíclicamente); la misma clave descifra: `XOR(XOR(datos, clave), clave) = datos`
- **Clave configurable** mediante el parámetro `--key` o `--key-file` (primera línea del fichero) — la clave por defecto es `VAMP_KEY_2026`
- **Filtrado por prefijo mágico** — el receptor ignora silenciosamente todo el tráfico ICMP que no lleve el prefijo `VSHDW:`, manteniéndose silencioso en entornos de tráfico mixto
- **Modo verbose** (`-v`) muestra todos los paquetes ICMP recibidos incluidos los que no tienen el prefijo mágico, útil para depurar la ubicación de reglas IDS
- **Fragmentación basada en chunks** — los mensajes más largos de 200 bytes ofuscados se dividen automáticamente; el receptor acumula chunks por IP de origen ordenados por número de secuencia ICMP
- **Verificación de privilegios root** — sale con un error si no se ejecuta como root, ya que la captura de paquetes raw requiere `CAP_NET_RAW`
- Salida Rich en consola: el emisor muestra una tabla por paquete con previsualización del payload, recuento de bytes y estado; el receptor muestra un panel por mensaje decodificado

### Requisitos

```
pip install -r requirements.txt
```

| Paquete | Versión |
|---------|---------|
| `scapy` | >= 2.5.0 |
| `rich`  | >= 13.7.0 |

Biblioteca estándar: `argparse`, `base64`, `os`, `sys`, `time`, `datetime`, `pathlib`.

### Instalación

```bash
git clone https://github.com/belky-me/vamp-icmp-shadow.git
cd vamp-icmp-shadow
pip install -r requirements.txt
```

Requiere root o la capacidad `CAP_NET_RAW` para los modos send y listen.

### Uso

```bash
python vamp_icmp_shadow.py --help
```

Hay dos subcomandos disponibles: `send` y `listen`.

```
uso: vamp-icmp-shadow {send,listen} ...

subcomandos:
  send      Enviar un mensaje por el canal ICMP Shadow
  listen    Escuchar el tráfico entrante del canal ICMP Shadow
```

### Ejemplos

**Enviar un mensaje corto a un objetivo de laboratorio (clave por defecto):**
```bash
sudo python vamp_icmp_shadow.py send -t 192.168.1.10 -d "shadow test"
```

**Enviar un mensaje con una clave XOR personalizada:**
```bash
sudo python vamp_icmp_shadow.py send -t 192.168.1.10 -d "exfil payload" -k "MY_SECRET_KEY"
```

**Enviar usando una clave cargada desde un fichero:**
```bash
sudo python vamp_icmp_shadow.py send -t 192.168.1.10 -d "test" --key-file /etc/lab/icmp.key
```

**Escuchar en la interfaz eth0 el tráfico entrante del canal Shadow:**
```bash
sudo python vamp_icmp_shadow.py listen -i eth0
```

**Escuchar con clave personalizada y modo verbose (muestra también ICMP no-Shadow):**
```bash
sudo python vamp_icmp_shadow.py listen -i eth0 -k "MY_SECRET_KEY" -v
```

### Descripción del protocolo

```
Emisor:
  texto plano → XOR(clave) → Base64 → "VSHDW:" + B64_CHUNK
  Cada chunk → ICMP Echo Request (type=8, seq=N, payload=VSHDW:...)

Receptor:
  ICMP Echo Request capturado → comprobar prefijo "VSHDW:"
  → decodificar Base64 → XOR(clave) → texto plano
  → mostrar con IP de origen y número de secuencia
```

Tamaño de chunk: 200 bytes de la cadena Base64 ofuscada por paquete.  
Retardo entre paquetes: 50 ms para evitar saturar la pila de red.

### Notas de detección para el Blue Team

Esta herramienta está diseñada para que su propio tráfico sea detectable. Ejemplo de firma Suricata que se activa con el prefijo mágico `VSHDW:` en payloads ICMP:

```
alert icmp any any -> any any (msg:"VampSecure ICMP Shadow channel"; \
  content:"VSHDW:"; itype:8; sid:9000001; rev:1;)
```

Usa esta herramienta para verificar que tu firma IDS se activa correctamente antes de incorporarla al ruleset de producción.

---

### Why vamp-icmp-shadow vs. hping3 · Scapy manual · nping

| Característica | vamp-icmp-shadow | hping3 | Scapy manual | nping |
|---------|:---:|:---:|:---:|:---:|
| Capa de ofuscación XOR+Base64 | ✅ | ❌ | ❌ | ❌ |
| Modo `listen` / decodificación integrado | ✅ | ❌ | ❌ | ❌ |
| Filtrado por prefijo mágico (ignora ICMP no relacionado) | ✅ | ❌ | ❌ | ❌ |
| Reensamblado de chunks en múltiples paquetes | ✅ | ❌ | ❌ | ❌ |
| Salida Rich con colores para sesiones de laboratorio | ✅ | ❌ | ❌ | ❌ |
| Soporte de fichero de clave (`--key-file`) | ✅ | ❌ | ❌ | ❌ |
| Ejemplo de detección Suricata integrado | ✅ | ❌ | ❌ | ❌ |
| Diseñado para flujos de validación de reglas IDS | ✅ | ⚠️ indirecto | ❌ | ⚠️ indirecto |

---

### Contexto de investigación y uso defensivo

Esta herramienta existe para **validación de reglas IDS/IPS** y ejercicios de laboratorio Red/Blue Team. La tabla a continuación mapea cada capacidad a su aplicación de investigación defensiva.

| Capacidad | Aplicación de investigación defensiva | Referencia |
|-----------|---------------------------------------|------------|
| Canal payload ICMP (`send`) | Demostrar que la exfiltración de datos por ICMP es posible en entornos de red permisivos | MITRE ATT&CK T1048 — Exfiltración por Protocolo Alternativo |
| Capa de ofuscación XOR | Probar si las reglas IDS detectan payloads ofuscados, no solo cadenas en texto plano | Cobertura de operadores `content` + `pcre` en Snort/Suricata |
| Marcador mágico (`VSHDW:`) | Generar un IOC conocido y determinístico para creación de reglas y pruebas de firmas | Match `content` de Suricata (`itype:8`) |
| Fragmentación por chunks en números de secuencia | Validar que el IDS reensambla streams ICMP antes de aplicar reglas de contenido | Configuración de reensamblado de stream en Suricata |
| Clave personalizada (`--key`, `--key-file`) | Simular rotación de clave por engagement; verificar que los cambios de clave no rompen la cobertura IDS | Simulación de seguridad operativa |
| Modo verbose en listener (`-v`) | Analizar todo el tráfico ICMP en la ventana de captura para localizar falsos negativos | Flujo de análisis de tráfico del Blue Team |
| Modo decode de `listen` | Confirmar que el Blue Team puede recuperar texto plano del tráfico ICMP capturado | Simulación de recolección de evidencia en IR |
| Verificación root / `CAP_NET_RAW` | Garantiza que la herramienta solo se ejecuta con los privilegios adecuados — evita fallos silenciosos | Verificación de control de acceso en laboratorio |
| Retardo de 50 ms entre paquetes | Evita saturar la pila de red; proporciona temporización reproducible para replay de PCAP | Pruebas de replay y regresión de IDS |

---

### Parte del toolkit VampSecure Labs

Esta herramienta forma parte del **VampSecure Labs Security Toolkit** — una colección de herramientas de seguridad de grado investigación para pruebas de penetración autorizadas y ejercicios red/blue team.

- Toolkit completo: [github.com/belky-me](https://github.com/belky-me)
- Orquestador: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.1 | README bilingüe (EN/ES) |
| v1.0 | Lanzamiento inicial — canal encubierto ICMP, ofuscación XOR+Base64, modos send/listen, ejemplo de detección Suricata |

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Solo para pruebas de seguridad autorizadas.
