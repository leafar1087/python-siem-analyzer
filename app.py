# app.py - Nuestro servidor web Flask

import json, sys, pandas as pd, traceback
# importamos el modulo render_template para poder renderizar nuestras plantillas HTML
from flask import Flask, request, jsonify, render_template
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

def generar_estadisticas():
    """
    Usa Pandas para leer el JSON y generar estadísticas.
    """
    try:
        # 1. Leemos el JSON. 'orient="records"' es la clave que arreglamos.
        df = pd.read_json("logs.json", orient="records")
        
        # 2. Comprobamos si el DataFrame está vacío (buena práctica)
        if df.empty:
            return {
                "total_logs": 0,
                "conteo_por_nivel": {},
                "top_5_ips": {}
            }

        # 3. Hacemos el análisis
        # (Usa aquí la clave que corregiste, ej. 'ip_origen' o 'ip')
        top_ips = df['ip'].value_counts().nlargest(5).to_dict()
        conteo_niveles = df['nivel'].value_counts().to_dict()
        
        # 4. Preparamos la respuesta de éxito
        stats = {
            "total_logs": int(len(df)), # int() es una buena práctica
            "conteo_por_nivel": conteo_niveles,
            "top_5_ips": top_ips
        }
        return stats

    except FileNotFoundError:
        print("[ERROR] No se encontró el archivo logs.json")
        return {"error": "No se encontró el archivo de logs."}
    except KeyError as e:
        # Si el error de 'ip_origen' regresa, esto lo atrapará
        print(f"[ERROR] KeyError en Pandas: {e}")
        return {"error": f"Discrepancia de nombres en logs.json. Falta la columna: {e}"}
    except Exception as e:
        # Un 'atrapa-todo' para cualquier otro error de Pandas o de archivo
        print(f"[ERROR] Error inesperado en generar_estadisticas: {e}")
        return {"error": str(e)}
    


# --- ENDPOINTS (RUTAS) DE NUESTRA APP
@app.route("/")
def index():
    # "... ejecuta esta funcion y devuelve el resultado al navegador"
    return render_template("index.html")

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

@app.route("/api/stats")
def get_stats():
    """
    Endpoint de la API para obtener las estadísticas.
    """
    # 1. Llama a la función de lógica
    estadisticas = generar_estadisticas()
    
    # 2. Comprobamos si nuestra función devolvió un error
    if "error" in estadisticas:
        # Si hay un error, devolvemos el JSON de error
        # y un código de estado 500 (Internal Server Error)
        return jsonify(estadisticas), 500
    
    # 3. Si todo va bien, devuelve el JSON con éxito (código 200 por defecto)
    return jsonify(estadisticas)


# INICIO DEL SERVIDOR

if __name__ == "__main__":
    # debug=True: nos permite ver los errores en el navegador y el servidor se reinicia automaticamente
    # port=5000: el puerto en el que se ejecutara el servidor
    app.run(debug=True, port=5000) 
