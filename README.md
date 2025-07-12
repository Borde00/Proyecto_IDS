# Proyecto_IDS

**Autor:** Borde00
**Fecha:** 2025-07-12

---

## Descripción

MyIDSProject es un **Sistema de Detección de Intrusiones (IDS)** en Python que monitoriza tráfico TCP en tiempo real y envía alertas a un canal de Discord mediante webhooks. Detecta:

- **SYN Flood** (inundación de paquetes SYN)  
- **Escaneo de puertos** (port scanning)  
- **Intentos de intrusión SSH**  
- **Ataques HTTP** (por ejemplo Slowloris)

---

## Estructura del proyecto

```text
IDS/
├── src/
│   └── IDS.py       # Script principal del IDS
├── docs/
│   └── architecture.md      # Diagrama y descripción de la arquitectura
├── .gitignore               # Archivos y carpetas ignorados por Git
├── README.md                # Este archivo
├── LICENSE                  # Licencia MIT
└── requirements.txt         # Dependencias Python
