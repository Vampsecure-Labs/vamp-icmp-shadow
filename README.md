# vamp-icmp-shadow

**VampSecure Labs — Security Research Division**  
Canal encubierto ICMP para laboratorio Red/Blue Team: exfiltración de datos en tráfico ICMP.

---

## Descripción

Herramienta de laboratorio que demuestra la técnica de canal encubierto (covert channel)
mediante paquetes ICMP Echo Request. Los datos se ofuscan con cifrado XOR + codificación
Base64 y se fragmentan en chunks de 200 bytes para ser transportados en el campo de payload
de los paquetes ICMP.

Diseñada para entornos de laboratorio Blue Team (detección de tráfico anómalo ICMP) y
Red Team (demostración de exfiltración encubierta). **No es una herramienta de comunicación
segura** — el cifrado XOR es simétrico y trivialmente reversible con la clave.

## Técnica implementada

```
Datos originales → XOR(clave) → Base64 → Prefijo "VSHDW:" → Payload ICMP
```

El receptor filtra paquetes ICMP type=8 con payload que comience por el prefijo VSHDW:,
extrae el payload, revierte Base64 y XOR, y reconstruye el mensaje original.

## Requisitos

- Python 3.9+
- Permisos de root / `CAP_NET_RAW` (necesario para Scapy)
- Dependencias: `scapy>=2.5.0`, `rich>=13.7.0`

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

```bash
# Enviar mensaje a través de canal ICMP
sudo python3 vamp_icmp_shadow.py send 192.168.1.100 "Mensaje secreto de laboratorio"

# Enviar con clave personalizada y modo verbose
sudo python3 vamp_icmp_shadow.py send 192.168.1.100 "Mensaje de test" --key MICLAVELAB --verbose

# Enviar con clave desde fichero
sudo python3 vamp_icmp_shadow.py send 192.168.1.100 "Test" --key-file clave.txt

# Escuchar en interfaz (receptor)
sudo python3 vamp_icmp_shadow.py listen eth0

# Escuchar con clave personalizada
sudo python3 vamp_icmp_shadow.py listen eth0 --key MICLAVELAB --verbose
```

## Opciones send

| Opción | Descripción |
|--------|-------------|
| `target` | IP del receptor |
| `data` | Mensaje a transmitir |
| `--key` | Clave XOR (por defecto: `VAMP_KEY_2026`) |
| `--key-file` | Fichero con la clave XOR |
| `--verbose` | Mostrar tabla detallada de chunks enviados |

## Opciones listen

| Opción | Descripción |
|--------|-------------|
| `interface` | Interfaz de red a escuchar |
| `--key` | Clave XOR (debe coincidir con el emisor) |
| `--key-file` | Fichero con la clave XOR |
| `--verbose` | Mostrar detalles de cada paquete capturado |

## Uso en laboratorio Blue Team

La herramienta está pensada para que los equipos de detección practiquen la identificación
de tráfico ICMP anómalo: payloads de longitud inusual, contenido Base64 en ICMP, frecuencia
irregular de Echo Requests.

## Aviso legal

**Uso exclusivo en entornos de laboratorio propios o con autorización escrita del propietario.**  
El uso de canales encubiertos en redes de producción sin autorización puede constituir un
delito. VampSecure Studios no se responsabiliza del uso indebido de esta herramienta.

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Licencia: MIT
