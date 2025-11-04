# Módulo 2.7: Modulos y paquetes
# main.py - nuestro script principal

# --- IMPORTACIONES ---
# Importamos la funcion obtener_severidad del modulo analyzer.py
from analyzer import obtener_severidad

print("--- Iniciando Analizador SIEM v0.5 (Modular) ---")


# --- DEFINICION DE DATOS ---
# (NUESTROS LOGS DE PRUEBA)

log_batch = [
    "INFO: 2025-11-04T20:01:00 - 192.168.1.1 - Conexión exitosa",
    "ERROR: 2025-11-04T20:02:15 - 10.0.0.5 - Fallo de autenticación",
    "INFO: 2025-11-04T20:02:30 - 192.168.1.1 - Desconexión",
    "WARN: 2025-11-04T20:03:00 - 10.0.0.5 - Intento de acceso a puerto 8080",
    "ERROR: 2025-11-04T20:04:10 - 10.0.0.5 - Fallo de autenticación",
    "ERROR: 2025-11-04T20:05:00 - 10.0.0.5 - Fallo de autenticación"
]

# --- DEFINICION DE FUNCIONES ---
#   Las funciones que definimos en analyzer.py ya no son necesarias aqui


# --- EJECUCION PRINCIPAL ---
# (EL 'CEREBRO' DEL PROGRAMA)

print("\n--- COMENZANDO ANALISIS EN LOTES ---")

for log_individual in log_batch:
    
    severidad = obtener_severidad(log_individual)
    print(f"Log: {log_individual} | Severidad: {severidad}")

    if severidad == "ALERTA":
        print(f"    [ALERTA] ACCION REQUERIDA: Enviando email al administrador")

print("--- ANALISIS DE LOGS FINALIZADO ---")
