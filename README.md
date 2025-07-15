# Proyecto_IDS

**Autor:** Borde00
**Fecha:** 2025-07-12

---

## Descripción

IDS es un **Sistema de Detección de Intrusiones (IDS)** en Python que monitoriza tráfico TCP en tiempo real y envía alertas a un canal de Discord mediante webhooks. Detecta:

- **SYN Flood** (inundación de paquetes SYN)  
- **Escaneo de puertos** (port scanning)  
- **Intentos de intrusión SSH**  
- **Ataques HTTP** (por ejemplo Slowloris)


---

⚠️ **Aviso legal**: Este código es solo para fines educativos y de investigación. Su uso contra sistemas sin autorización es ilegal y puede acarrear responsabilidades.

---

> **Este proyecto es una base en constante evolución**  
> Estoy iterando y ampliando funcionalidades con regularidad.  
> 
> Si tienes ideas, sugerencias o quieres usar este código en tus propios proyectos, ¡escríbeme!
>
> 
## Estructura del proyecto

```text
IDS/
├── src/
│   └── IDS.py       # Script principal del IDS
├── docs/
│   └── architecture.md      # Diagrama y descripción de la arquitectura
├── .gitignore               # Archivos y carpetas ignorados por Git
├── README.md                
├── LICENSE                  # Licencia MIT
└── requirements.txt         # Dependencias Python
