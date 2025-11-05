# main.py - nuestro script principal

# --- IMPORTACIONES ---
import json # Importamos el modulo json para leer el archivo logs.json
from models import LogEvent, ErrorLogEvent, WarnLogEvent, InfoLogEvent # Importamos las clases LogEvent, ErrorLogEvent, WarnLogEvent y InfoLogEvent
# Modulo 4.5: gestion de excepciones
import sys

print("--- Iniciando Analizador SIEM v1.0 (JSON y manejo de errores) ---")


# ---  DEFINICION DE DATOS ---
# ya no escribimos los datos, los leemos
# usamos un bloque try-except para manejar errores

log_data_cruda = [] # inicializamos la lista vacia
nombre_archivo = "logs.json"

try:
    # 'with open(...)': Es la forma correcta de abrir archivos en Python
    # 'r' significa 'read' (leer)
    with open(nombre_archivo, "r") as f:
        # json.load(f): Lee el archivo 'f' y lo convierte
        # en una esrtuctura dedatos de Python (en este caso, una lista de dicts)
        log_data_cruda = json.load(f)
    print(f"Cargados {len(log_data_cruda)} logs correctamente desde {nombre_archivo}")

except FileNotFoundError:
    print(f"[ERROR CRITICO]: El archivo {nombre_archivo} no existe")
    print("Por favor, asegurese de que el archivo existe y que el nombre es correcto")
    print("Programa terminado.")
    sys.exit(1) # sale del programa con un codigo de error 1 (1 es el codigo de error para errores criticos)

except json.JSONDecodeError:
    print(f"[ERROR CRITICO]: El archivo {nombre_archivo} no es un archivo JSON valido")
    print("Por favor, asegurese de que el archivo es un archivo JSON valido")
    print("Programa terminado.")
    sys.exit(1) # sale del programa con un codigo de error 1 (1 es el codigo de error para errores criticos)


# --- TRANSFORMACION DE DATOS ---
# 

print("\n--- TRANSFORMANDO DATOS CRUDOS A OBJETOS LOG ---")
lista_de_objetos_log = []
for log_dict in log_data_cruda:


    # extraemos los datos comunes del diccionario
    timestamp=log_dict['timestamp']
    nivel=log_dict['nivel']
    mensaje=log_dict['mensaje']
    ip=log_dict['ip']
    

    # Decidimos que tipo de objeto crear basado en el nivel del log
    if nivel == "ERROR":
        nuevo_log_obj = ErrorLogEvent(timestamp, nivel, mensaje, ip)
    elif nivel == "WARN":
        nuevo_log_obj = WarnLogEvent(timestamp, nivel, mensaje, ip)
    else:
        nuevo_log_obj = InfoLogEvent(timestamp, nivel, mensaje, ip)


    lista_de_objetos_log.append(nuevo_log_obj)

# --- EJECUCION PRINCIPAL ---
print("\n--- COMENZANDO ANALISIS EN LOTES ---")

# iteramos sobre nuestra lista de objetos

for log in lista_de_objetos_log:

    # ESTA LINEA NO CAMBIA NADA
    # aunque 'log' es un ErrorLogEvent, WarnLogEvent o InfoLogEvent,
    # heredó el metodo obtener_severidad() de LogEvent
    severidad = log.obtener_severidad() # Llamamos al metodo del objeto

    print(f"Log: {log.timestamp} | IP: {log.ip} | Nivel: {severidad}")

    if "ALERTA" in severidad:
        print(f"    ACCION REQUERIDA: Mensaje: {log.mensaje}")

    if "AVISO" in severidad:
        print(f"    ACCION REQUERIDA: Mensaje: {log.mensaje}")

print("--- ANALISIS DE LOGS FINALIZADO ---")
