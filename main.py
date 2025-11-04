# Módulo 2.5: Diccionarios (dict)
# main.py - nuestro script principal

# --- IMPORTACIONES ---
# Importamos la funcion obtener_severidad del modulo analyzer.py
from analyzer import obtener_severidad

print("--- Iniciando Analizador SIEM v0.6 (Con diccionarios) ---")


# --- DEFINICION DE DATOS ---
# Lista de diccionarios

log_batch = [
    {
        "timestamp": "2025-11-04T20:01:00",
        "nivel": "INFO",
        "mensaje": "Conexión exitosa",
        "ip": "192.168.1.1"
    },
    {
        "timestamp": "2025-11-04T20:02:15",
        "nivel": "ERROR",
        "mensaje": "Fallo de autenticación",
        "ip": "10.0.0.5"
    },
    {
        "timestamp": "2025-11-04T20:02:30",
        "nivel": "INFO",
        "mensaje": "Desconexión",
        "ip": "192.168.1.1"
    },
    {
        "timestamp": "2025-11-04T20:03:00",
        "nivel": "WARN",
        "mensaje": "Intento de acceso a puerto 8080",
        "ip": "10.0.0.5"
    },
    {
        "timestamp": "2025-11-04T20:04:10",
        "nivel": "ERROR",
        "mensaje": "Fallo de autenticación",
        "ip": "10.0.0.5"
    },
    {
        "timestamp": "2025-11-04T20:05:00",
        "nivel": "ERROR",
        "mensaje": "Fallo de autenticación",
        "ip": "10.0.0.5"
    }
]

# --- EJECUCION PRINCIPAL ---
# (EL 'CEREBRO' DEL PROGRAMA)

print("\n--- COMENZANDO ANALISIS EN LOTES ---")

for log in log_batch:
    # 'log' ya no es string, es un diccionario
    # tenemos que pasarle el diccionario completo a nuestra funcion obtener_severidad
    severidad = obtener_severidad(log)

    # Usamos e acceso por clave para imprimir de forma ordenada
    print(f"Log: {log['timestamp']} | IP: {log['ip']} | Nivel: {log['nivel']}")

    if severidad == "ALERTA":
        print(f"    [ALERTA] ACCION REQUERIDA: Mensaje: {log['mensaje']}")

print("--- ANALISIS DE LOGS FINALIZADO ---")
