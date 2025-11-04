# Módulo 2.6. FUNCIONES (con 'return' y 'annotations')

print("--- Iniciando Analizador SIEM v0.4 (Buenas practicas) ---")


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

# Introducimos 'Annotations' (Type Hinting)
# (log_a_procesar: str) -> str significa que el parametro log_a_procesar debe ser un string y que la funcion devuelve un string

def obtener_severidad(log_a_procesar: str) -> str:

    """
    Analiza un unico string de log y DEVUELVE su severidad
    """

    print(f"Procesando log: {log_a_procesar}")
    
    if "ERROR" in log_a_procesar or "Fallo" in log_a_procesar:
        return "ALERTA" # EN LUGAR DE IMPRIMIR, devolvemos la cadena "ALERTA"
    elif "WARN" in log_a_procesar or "Advertencia" in log_a_procesar:
        return "AVISO" # EN LUGAR DE IMPRIMIR, devolvemos la cadena "AVISO"
    else:
        return "INFORMACION" # EN LUGAR DE IMPRIMIR, devolvemos la cadena "INFORMACION"

# --- EJECUCION PRINCIPAL ---
# (EL 'CEREBRO' DEL PROGRAMA)

print("--- Comenzando analisis en lotes ---")

for log_individual in log_batch:
    # 1. Llamamos a la funcion y capturamos su resultado en una variable
    severidad = obtener_severidad(log_individual)

    # 2. Ahora el bucle principal decide que hacer con el resultado
    print(f"Log: {log_individual} | Severidad: {severidad}")

    # Podemos tomar decisiones basadas en el resutado
    if severidad == "ALERTA":
        print(f"    [ALERTA] Se ha detectado un evento critico en seguridad. Enviando email al administrador")

print("--- ANALISIS DE LOGS FINALIZADO ---")
