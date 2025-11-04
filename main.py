# MODULO 2.1: FUNDAMENTOS DE PYTHON
# PROYECTO: ANALIZADOR SIEM
# AUTOR: RAFAEL ANTONIO PEREZ LLORCA
# FECHA: 04/11/2025

# 1.VARIABLES DE TIPO STRING(str)

ip_origen = "192.168.1.1"
usuario = "raperez"
evento_log = "Fallo de autenticacion"

# 2.VARIABLES DE TIPO INTEGER(int)

intentos_fallidos = 1
puerto_destino = 8080

# 3.VARIABLES DE TIPO BOOLEANO(bool)

es_critico = True
sesion_iniciada = False

# 4. MODULO 2.4: CONTROL DE FLUJO (DECISIONES)

print("--- Inciando Analizador SIEM ---")

# Decisión 1: Es un evento critico?
# Comparamos un booleano directamente

if es_critico == False:
# if es_critico:
    print(f"[ALERTA] Evento critico detectado {evento_log}")

    # Decision 2: ya ques es crítico, veamos que tan grave es
    # Usamos un operador de comparación numerico para ver si el numero de intentos es mayor a 3
    if intentos_fallidos >= 3:
        print(f"[Prioridad ALTA] Muchos intentos fallidos ({intentos_fallidos}) desde {ip_origen}")
    else:
        print(f"[Prioridad MEDIA] {intentos_fallidos} intento(s) fallido(s) desde {ip_origen}")

# Decision 3: ¿Qué hacemos si el evento no es critico?
else:
    print(f"[INFORMACION] Evento no critico: {evento_log}")

# Decision 4: Usando 'elif' para manejar otros casos (contraccion de 'else if')

print("--- Análisis de puertos ---")

if puerto_destino == 80:
    print(f"Protocolo: HTTP (no seguro)")
elif puerto_destino == 443:
    print(f"Protocolo: HTTPS (seguro)")
elif puerto_destino == 22:
    print(f"Protocolo: SSH (Acceso remoto)")
else:
    print(f"Protocolo: Desconocido ({puerto_destino})")

