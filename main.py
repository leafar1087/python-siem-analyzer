# main.py - nuestro script principal

# --- IMPORTACIONES ---
from analyzer import obtener_severidad
from models import LogEvent # Importamos la clase LogEvent

print("--- Iniciando Analizador SIEM v0.7 (Orientado a objetos) ---")


# --- DEFINICION DE DATOS ---
# Lista de diccionarios

log_data_cruda = [
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

# --- TRANSFORMACION DE DATOS (NUEVO PASO) ----
print("\n--- TRANSFORMANDO DATOS CRUDOS A OBJETOS LOG ---")
lista_de_objetos_log = []
for log_dict in log_data_cruda:
    # Se crea el objeto
    # Llamamos a la clase como si fuera una funcion
    # Esto ejecuta automaticamente el metodo __init__

    nuevo_log_obj = LogEvent(
        timestamp=log_dict['timestamp'],
        nivel=log_dict['nivel'],
        mensaje=log_dict['mensaje'],
        ip=log_dict['ip']
    )

    lista_de_objetos_log.append(nuevo_log_obj)

# --- EJECUCION PRINCIPAL ---
print("\n--- COMENZANDO ANALISIS EN LOTES ---")

# iteramos sobre nuestra lista de objetos

for log in lista_de_objetos_log:
    severidad = obtener_severidad(log)

    print(f"Log: {log.timestamp} | IP: {log.ip} | Nivel: {log.nivel}")

    if severidad == "ALERTA":
        print(f"    [ALERTA] ACCION REQUERIDA: Mensaje: {log.mensaje}")

    if severidad == "AVISO":
        print(f"    [AVISO] ACCION REQUERIDA: Mensaje: {log.mensaje}")

print("--- ANALISIS DE LOGS FINALIZADO ---")
