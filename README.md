# 🛡️ Proyecto_IDS — Sistema de Detección de Intrusiones

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-orange.svg)](https://scapy.net/)
[![Discord](https://img.shields.io/badge/Discord-Webhook-5865F2.svg)](https://discord.com/)

IDS ligero en Python que detecta ataques en tráfico TCP y envía alertas en tiempo real a Discord mediante Webhooks.

---

## ✨ Características

- **Captura en tiempo real** de paquetes TCP con Scapy.
- **Detección automática** de:
  - SYN Flood
  - Port Scan
  - Ataques HTTP (múltiples conexiones, posible Slowloris)
  - Intentos de intrusión SSH (fuerza bruta)
- **Notificaciones instantáneas** a Discord con embeds enriquecidos.
- **Bloqueo temporal por IP** para evitar spam de alertas.
- **Limpieza periódica** de registros en segundo plano.
- **Identificación automática** de la IP local del servidor.

---

## 📦 Requisitos

- Python 3.8 o superior
- Permisos de root / administrador (para captura en modo promiscuo)
- Dependencias de Python:

```bash
pip install -r requirements.txt
```

> **Nota:** `scapy` requiere permisos elevados para capturar paquetes en la interfaz de red.

---

## 🚀 Instalación

1. Clona o descarga el repositorio:
```bash
git clone https://github.com/Borde00/Proyecto_IDS.git
cd Proyecto_IDS
```

2. Instala las dependencias:
```bash
pip install -r requirements.txt
```

3. Configura tu Webhook de Discord (ver siguiente sección).

---

## ⚙️ Configuración

Edita el archivo `IDS.py` y modifica la siguiente variable con tu propia URL de Webhook de Discord:

```python
WEBHOOK_URL = "https://discord.com/api/webhooks/TU_WEBHOOK_AQUI"
```

Opcionalmente, puedes ajustar los umbrales de detección:

```python
THRESHOLD_SYN_FLOOD = 30      # Paquetes SYN
THRESHOLD_PORT_SCAN = 10      # Puertos distintos
THRESHOLD_HTTP_CONN = 20      # Conexiones en 10 segundos
TIEMPO_BLOQUEO = 300          # Segundos entre alertas repetidas por IP
```

---

## ▶️ Uso

Ejecuta el script con permisos de administrador:

```bash
sudo python3 IDS.py
```

Verás en consola:
```
[+] IDS activado en 192.168.1.100 (2026-06-30 13:38:00) - Escuchando tráfico TCP...
```

Cuando se detecte un ataque, se enviará automáticamente una alerta al canal de Discord configurado.

---

## 🏗️ Arquitectura

El sistema se compone de 4 módulos principales:

| Módulo | Descripción |
|--------|-------------|
| **Captura** | Scapy en modo promiscuo filtra paquetes TCP (puertos 80 y 22). |
| **Análisis** | Contadores por IP: SYN, puertos distintos, conexiones HTTP, intentos SSH. |
| **Alertas** | Cuando un contador supera su umbral, genera alerta y marca la IP como "alertada". |
| **Notificaciones** | Envía embeds a Discord vía `discord-webhook`. |

Un hilo daemon limpia registros expirados cada 60 segundos.

> Para más detalles, consulta [`architecture.md`](architecture.md).

---

## 🎯 Tipos de ataque detectados

| Tipo | Descripción | Umbral |
|------|-------------|--------|
| **SYN_FLOOD** | Saturación con paquetes SYN | 30 SYN |
| **PORT_SCAN** | Escaneo de múltiples puertos | 10 puertos distintos |
| **HTTP** | Múltiples conexiones HTTP en 10s | 20 conexiones |
| **SSH** | Intento de intrusión en puerto 22 | 1 intento |

---

## 🎬 Video de demostración

A continuación se muestra una demostración del sistema en funcionamiento:

> 🎥 **[Ver video de demostración](https://drive.google.com/file/d/1CfmtVcMhw_VbFEgau82pbbW0utSlD61t/view?usp=sharing)**

### Capturas del panel de Discord

```
┌─────────────────────────────────────────┐
│  🚨 [SYN_FLOOD] Ataque Detectado        │
│  Servidor IDS: 192.168.1.100            │
│  IP Atacante: 10.0.0.5                  │
│  Puerto objetivo: 80                    │
│  Fecha/Hora: 2026-06-30 13:45:22       │
└─────────────────────────────────────────┘
```

---

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Consulta el archivo [`LICENSE.md`](LICENSE.md) para más detalles.

---
