# Arquitectura de Proyecto_IDS

Este documento explica el diseño y flujo de datos de **Proyecto_IDS**, un IDS que detecta ataques en tráfico TCP y notifica vía Discord.

---

## 1. Componentes principales

1. **Captura de paquetes**  
   - Utiliza **Scapy** en modo promiscuo para interceptar paquetes TCP de la interfaz de red.  
   - Filtra solo paquetes con flag SYN, puertos HTTP (80) o SSH (22).

2. **Módulo de análisis**  
   - Mantiene contadores por dirección IP en estructuras de datos en memoria:  
     - Paquetes SYN recibidos (para SYN Flood)  
     - Puertos distintos contactados (para Port Scan)  
     - Conexiones HTTP en ventana de 10 s  
     - Intentos SSH  
   - Cuando un contador supera su umbral (`THRESHOLD_*`), marca la IP como “alertada”.

3. **Gestión de alertas y bloqueo temporal**  
   - Registra timestamp de la última alerta por IP.  
   - Un hilo daemon limpia periódicamente los registros cuya última actividad supere `TIEMPO_BLOQUEO` segundos, permitiendo nuevas alertas posteriores.

4. **Envío de notificaciones a Discord**  
   - Utiliza **discord-webhook** para formatear un embed con:  
     - Tipo de ataque  
     - IP origen  
     - Contador o puertos involucrados  
     - Timestamp  
   - Envía el embed al canal configurado por `WEBHOOK_URL`.

---

## 2. Flujo de ejecución

```text
┌─────────────────────────┐
│  Inicio del script      │
│ - Carga configuración   │
│ - Inicializa estructuras│
│ - Lanza hilo de limpieza│
└───────┬─────────────────┘
        │
        ▼
┌─────────────────────────┐
│  Sniffer Scapy          │
│ - Captura paquete TCP   │
│ - Filtra por puertos    │
└───────┬─────────────────┘
        │
        ▼
┌─────────────────────────┐
│  Análisis por IP        │
│  - Incrementa contadores│
│  - Comprueba umbrales   │
└───────┬─────────────────┘
        │
   [ umbral superado? ]
        ├── No ──► Ignorar
        │
        └── Sí ──► Generar alerta
                    │
                    ▼
        ┌─────────────────────────┐
        │  Enviar notificación    │
        │  (discord-webhook)      │
        └─────────────────────────┘
