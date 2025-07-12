#!/usr/bin/env python3
from scapy.all import sniff, TCP, IP
from datetime import datetime
import time
import threading
from discord_webhook import DiscordWebhook, DiscordEmbed
from threading import Lock
from collections import defaultdict
import socket

# Función para obtener IP real del servidor (no 127.x.x.x)
def obtener_ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "IP no disponible"

# Configuración
WEBHOOK_URL = "https://discord.com/api/webhooks/1377731260532785263/7lirhbVWIIIvDO2kU9hYTCtqOpmiVbuA3um2urMNT8sr2isez0jUAgpCVn94_5xnmr15"
IP_LOCAL = obtener_ip_local()
TIEMPO_BLOQUEO = 300
THRESHOLD_SYN_FLOOD = 30
THRESHOLD_PORT_SCAN = 10
THRESHOLD_HTTP_CONN = 20

registro_ataques = {}
alertas_enviadas = {}
registro_http = defaultdict(list)
lock = Lock()

def obtener_descripcion(tipo):
    return {
        "HTTP": "Ataque HTTP detectado. Múltiples conexiones sospechosas al puerto 80. Posible Slowloris u otra técnica.",
        "SSH": "Intento de intrusión en SSH (puerto 22). Posible ataque de fuerza bruta.",
        "SYN_FLOOD": "Ataque SYN Flood detectado. Saturación por paquetes SYN.",
        "PORT_SCAN": "Escaneo de puertos detectado. Reconocimiento de red en curso."
    }.get(tipo, "Ataque desconocido")

def enviar_notificacion(tipo, ip, puerto, detalles):
    thumbs = {
        "HTTP":      "https://cdn4.iconfinder.com/data/icons/network-security-4/512/N_T_1142Artboard_1_copy_11-512.png",
        "SSH":       "https://cdn4.iconfinder.com/data/icons/network-security-4/512/N_T_1142Artboard_1_copy_11-512.png",
        "SYN_FLOOD": "https://cdn4.iconfinder.com/data/icons/network-security-4/512/N_T_1142Artboard_1_copy_11-512.png",
        "PORT_SCAN": "https://cdn4.iconfinder.com/data/icons/network-security-4/512/N_T_1142Artboard_1_copy_11-512.png"
    }
    thumb_url = f"{thumbs.get(tipo)}?v={int(time.time())}"

    webhook = DiscordWebhook(url=WEBHOOK_URL)
    embed = DiscordEmbed(
        title=f"🚨 [{tipo}] Ataque Detectado",
        description=f"**Servidor IDS:** `{IP_LOCAL}`\n**IP Atacante:** `{ip}`\n\n{detalles}",
        color={
            "HTTP": "F44336",
            "SSH": "2196F3",
            "SYN_FLOOD": "9C27B0",
            "PORT_SCAN": "FF9800"
        }.get(tipo, "607D8B")
    )
    embed.set_thumbnail(url=thumb_url)
    embed.add_embed_field(name="Puerto objetivo", value=f"`{puerto}`", inline=True)
    embed.add_embed_field(name="Fecha/Hora", value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), inline=False)
    embed.set_footer(
        text="Sistema de Detección de Intrusiones",
        icon_url="https://cdn3.iconfinder.com/data/icons/computing-technology/74/Hacker_computer-RAD-512.png"
    )
    try:
        webhook.add_embed(embed)
        webhook.execute()
        print(f"[ALERTA ENVIADA] {tipo} desde IP {ip}:{puerto} (Servidor: {IP_LOCAL})")
    except Exception as e:
        print(f"[ERROR] Alerta no enviada para IP {ip}:{puerto}: {e}")

def limpiar_registros():
    while True:
        time.sleep(60)
        ahora = datetime.now()
        with lock:
            for ip in list(registro_ataques):
                if (ahora - registro_ataques[ip]["ultimo"]).total_seconds() > TIEMPO_BLOQUEO:
                    del registro_ataques[ip]
            for ip in list(alertas_enviadas):
                if (ahora - alertas_enviadas[ip]["ultimo_envio"]).total_seconds() > TIEMPO_BLOQUEO:
                    del alertas_enviadas[ip]
            for ip in list(registro_http):
                registro_http[ip] = [t for t in registro_http[ip] if (ahora - t).total_seconds() <= 10]

def analizar_paquete(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    ip_src = packet[IP].src
    dport = packet[TCP].dport
    flags = packet[TCP].flags
    ahora = datetime.now()

    with lock:
        if ip_src not in registro_ataques:
            registro_ataques[ip_src] = {
                "ultimo": ahora,
                "syn_count": 0,
                "ports": set()
            }
        registro_ataques[ip_src]["ultimo"] = ahora

        if flags & 0x02:
            registro_ataques[ip_src]["syn_count"] += 1
            if registro_ataques[ip_src]["syn_count"] >= THRESHOLD_SYN_FLOOD:
                if ip_src not in alertas_enviadas or alertas_enviadas[ip_src]["tipo"] != "SYN_FLOOD":
                    enviar_notificacion("SYN_FLOOD", ip_src, dport, obtener_descripcion("SYN_FLOOD"))
                    alertas_enviadas[ip_src] = {"tipo": "SYN_FLOOD", "ultimo_envio": ahora}
                registro_ataques[ip_src]["syn_count"] = 0

        registro_ataques[ip_src]["ports"].add(dport)
        if len(registro_ataques[ip_src]["ports"]) >= THRESHOLD_PORT_SCAN:
            if ip_src not in alertas_enviadas or alertas_enviadas[ip_src]["tipo"] != "PORT_SCAN":
                enviar_notificacion("PORT_SCAN", ip_src, "múltiples", obtener_descripcion("PORT_SCAN"))
                alertas_enviadas[ip_src] = {"tipo": "PORT_SCAN", "ultimo_envio": ahora}
            registro_ataques[ip_src]["ports"].clear()

        if dport == 22:
            if ip_src not in alertas_enviadas or alertas_enviadas[ip_src]["tipo"] != "SSH":
                enviar_notificacion("SSH", ip_src, dport, obtener_descripcion("SSH"))
                alertas_enviadas[ip_src] = {"tipo": "SSH", "ultimo_envio": ahora}

        if dport == 80:
            registro_http[ip_src].append(ahora)
            registro_http[ip_src] = [t for t in registro_http[ip_src] if (ahora - t).total_seconds() <= 10]
            if len(registro_http[ip_src]) >= THRESHOLD_HTTP_CONN:
                if ip_src not in alertas_enviadas or alertas_enviadas[ip_src]["tipo"] != "HTTP":
                    enviar_notificacion("HTTP", ip_src, dport, obtener_descripcion("HTTP"))
                    alertas_enviadas[ip_src] = {"tipo": "HTTP", "ultimo_envio": ahora}
                registro_http[ip_src].clear()

def iniciar_sniffer():
    print(f"[+] IDS activado en {IP_LOCAL} ({datetime.now()}) - Escuchando tráfico TCP...")
    sniff(filter="tcp", prn=analizar_paquete, store=0)

if __name__ == "__main__":
    threading.Thread(target=limpiar_registros, daemon=True).start()
    iniciar_sniffer()