# app.py - Nuestro servidor web Flask

import json, sys
from flask import Flask, request, jsonify
from models import LogEvent, ErrorLogEvent, WarnLogEvent, InfoLogEvent

# 1. Creamos la aplicacion Flask
app = Flask(__name__)


# --- DEFINICION DE DATOS ---
# la logica de main.py la llevamos a app.py
# la convertimos en una funcion para poder llamarla cuando queramos
# usamos un bloque try-except para manejar errores

def cargar_y_analizar_logs():
    log_data_cruda = [] # inicializamos la lista vacia
    nombre_archivo = "logs.json"

    try:
    
        with open(nombre_archivo, "r") as f:
            log_data_cruda = json.load(f)
    
    except FileNotFoundError:
        print(f"[ERROR CRITICO]: El archivo {nombre_archivo} no existe")
        return []

    except json.JSONDecodeError:
        print(f"[ERROR CRITICO]: El archivo {nombre_archivo} no es un archivo JSON valido")
        return []

    # --- TRANSFORMACION DE DATOS ---
 
    lista_de_objetos_log = []
    for log_dict in log_data_cruda:
        timestamp=log_dict['timestamp']
        ip=log_dict['ip']
        mensaje=log_dict['mensaje']
        nivel=log_dict['nivel']
   
        if nivel == "ERROR":
            nuevo_log_obj = ErrorLogEvent(timestamp, nivel, mensaje, ip)
        elif nivel == "WARN":
            nuevo_log_obj = WarnLogEvent(timestamp, nivel, mensaje, ip)
        else:
            nuevo_log_obj = InfoLogEvent(timestamp, nivel, mensaje, ip)

        lista_de_objetos_log.append(nuevo_log_obj)

    return lista_de_objetos_log

# --- ENDPOINTS (RUTAS) DE NUESTRA APP
@app.route("/")
def index():
    # "... ejecuta esta funcion y devuelve el resultado al navegador"
    return "Bienvenido al Servidor del Analizador SIEM"

@app.route("/api/logs")
def get_logs():
    #1. Ejecutamos toda nuestra logica de POO
    lista_de_objetos_log = cargar_y_analizar_logs()

    #2. Convertimos nuestros objetos log en diccionarios
    # el navegador no entiende un objeto de python, pero sí un diccionario/JSON

    logs_como_diccionarios = []
    for log in lista_de_objetos_log:
        logs_como_diccionarios.append({
            "timestamp": log.timestamp,
            "ip": log.ip,
            "mensaje": log.mensaje,
            "severidad": log.obtener_severidad() # llamamos al metodo del objeto
        })

    # 3. Devolvemos la lista de diccionarios como JSON
    # 'jsonify' convierte nuestra lista de Python en una respuesta JSON
    # que el navegador puede entender.

    return jsonify(logs_como_diccionarios)


# INICIO DEL SERVIDOR

if __name__ == "__main__":
    # debug=True: nos permite ver los errores en el navegador y el servidor se reinicia automaticamente
    # port=5000: el puerto en el que se ejecutara el servidor
    app.run(debug=True, port=5000) 
