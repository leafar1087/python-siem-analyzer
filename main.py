# Módulo 2.5: Tipos de Datos avanzados (listas, tuplas, diccionarios)
# Modulo 2.4: Control de flujo (bucles)

print(f"--- Iniciando Analizador SIEM v0.2 (Procesamiento por Lotes) ---")

# 1. Una lista de logs (tipo 'list')
# en lugar de un solo string, ahora tenemos una lista de strings

log_batch = [
    "INFO: 2025-11-04T20:01:00 - 192.168.1.1 - Conexión exitosa",
    "ERROR: 2025-11-04T20:02:15 - 10.0.0.5 - Fallo de autenticación",
    "INFO: 2025-11-04T20:02:30 - 192.168.1.1 - Desconexión",
    "WARN: 2025-11-04T20:03:00 - 10.0.0.5 - Intento de acceso a puerto 8080",
    "ERROR: 2025-11-04T20:04:10 - 10.0.0.5 - Fallo de autenticación",
    "ERROR: 2025-11-04T20:05:00 - 10.0.0.5 - Fallo de autenticación"
]

# 2. Accediendo a elementos de la lista (por indice)
# Python empieza a contar desde 0, por lo que el primer elemento es el 0, el segundo es el 1, etc.

print(f"Primer log: {log_batch[0]}")
print(f"Segundo log: {log_batch[1]}")
print(f"Ultimo log: {log_batch[-1]}")

# Tambien podemos saber cuantos logs tenemos en la lista
print(f"Total de logs a analizar: {len(log_batch)}")

# 3. Iterando sobre la lista (usando bucles)
# Un bucle es un bloque de codigo que se ejecuta repetidamente hasta que se cumple una condicion
# Usamos la palabra clave 'for' para iterar sobre la lista
# La variable 'log' va tomando sucesivamente cada elemento de la lista

print("--- Analizando logs ---")
for log in log_batch:
    print(f"Procesando log: {log}")

    # Reutilizamos nuestra logica if/elif/else de la leccion anterior
    # Pero ahora lo aplicamos a la variable 'log' que contiene cada log de la lista

    if "ERROR" in log or "Fallo" in log:
        print(f"    [ALERTA] Se ha detectado un evento critico en seguridad")
    elif "WARN" in log or "Advertencia" in log:
        print(f"    [AVISO] Evento de advertencia detectado")
    
    # No necesitamos else paa los INFO, ya que no son eventos críticos

print("--- Fin del analisis de logs ---")

