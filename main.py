# Módulo 2.5: Tipos de Datos avanzados (listas, tuplas, diccionarios)
# Modulo 2.4: Control de flujo (bucles)

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

# Implememntacion  de la funcion analizar_log(log_a_procesar)
# 'log_a_procesar' es un PARAMETRO de la funcion

def analizar_log(log_a_procesar):

    """
    Este es un 'docstring'
    Analiza un unico string de log e imprime su severidad
    """

    print(f"Procesando log: {log_a_procesar}")
    
    if "ERROR" in log_a_procesar or "Fallo" in log_a_procesar:
        print(f"    [ALERTA] Se ha detectado un evento critico en seguridad")
    elif "WARN" in log_a_procesar or "Advertencia" in log_a_procesar:
        print(f"    [AVISO] Evento de advertencia detectado")
    
    # No necesitamos else paa los INFO, ya que no son eventos críticos

# --- EJECUCION PRINCIPAL ---
# (EL 'CEREBRO' DEL PROGRAMA)

print("--- Iniciando Analizador SIEM v0.3 (Procesamiento por Lotes) ---")

# Iteramos sobre cada log en la lista de logs de prueba
for log in log_batch:
    # Llamamos a la funcion analizar_log con el log actual
    analizar_log(log)

print("--- ANALISIS DE LOGS FINALIZADO ---")
