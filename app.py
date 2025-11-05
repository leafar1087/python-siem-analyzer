# app.py - Nuestro servidor web Flask

import json, sys, pandas as pd, traceback
# importamos el modulo render_template para poder renderizar nuestras plantillas HTML
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from models import LogEvent, ErrorLogEvent, WarnLogEvent, InfoLogEvent
# ... (importaciones existentes)

# --- Nuevas importaciones para la Capa 0: Seguridad ---
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash


# --- FORMULARIO DE LOGIN (CAPA 0) ---

class LoginForm(FlaskForm):
    """Define los campos y validadores para el formulario de login."""
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar Sesión')


# 1. Creamos la aplicacion Flask
app = Flask(__name__)

# --- CONFIGURACIÓN DE SEGURIDAD (CAPA 0) ---

# 1. Clave Secreta (¡CRÍTICA!)
# ¡Reemplaza esto con tu propia cadena aleatoria!
# Ejecuta este comando en tu terminal para obtener una:
# python3 -c 'import os; print(os.urandom(24).hex())'
app.config['SECRET_KEY'] = '2fc93db7443a0a85ab29eb58216685842d19d29cd4252720'

# 2. Configuración de la Base de Datos (SQLite)
# Esto le dice a Flask que cree un archivo llamado 'users.db' en tu proyecto.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# 3. Inicialización de los objetos
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, inicia sesión para acceder a esta página.'
# app.config['WTF_CSRF_SECRET_KEY'] = app.config['SECRET_KEY']

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    # Almacenamos la contraseña cifrada
    password_hash = db.Column(db.String(200), nullable=False)

    # --- NUEVOS METODOS DE CONTRASEÑA ---
    def set_password(self, password):
        # Ciframos la contraseña usando generate_password_hash
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        # Verificamos la contraseña usando check_password_hash
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    # Le dice a Flask login cómo cargar un usuario
    
    return User.query.get(int(user_id))

    



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

# --- RUTAS DE AUTENTICACIÓN (CAPA 0) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Si el usuario ya está logueado, lo mandamos al dashboard
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm() # Creamos una instancia de nuestro formulario
    
    # Si el formulario se envía (POST) y es válido
    if form.validate_on_submit():
        # 1. Buscamos al usuario en la BD
        user = User.query.filter_by(username=form.username.data).first()
        
        # 2. Comprobamos si el usuario existe Y si la contraseña es correcta
        if user and user.check_password(form.password.data):
            # 3. Si es correcto, iniciamos sesión con Flask-Login
            login_user(user) # ¡La magia de Flask-Login!
            
            # 4. Redirigimos al dashboard (ruta 'index')
            return redirect(url_for('index'))
        else:
            # 5. Si no, mostramos un error
            flash('Usuario o contraseña incorrectos')
            
    # Si es un GET (primera vez que carga) o si el login falló,
    # mostramos la plantilla HTML
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required # Solo un usuario logueado puede des-loguearse
def logout():
    logout_user() # ¡La otra magia de Flask-Login!
    return redirect(url_for('login'))

@app.route("/")
@login_required # Solo un usuario logueado puede ver el dashboard
def index():
    # "... ejecuta esta funcion y devuelve el resultado al navegador"
    return render_template("index.html")

@app.route("/api/logs")
@login_required # Solo un usuario logueado puede ver los logs
def get_logs():

    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
    except ValueError:
        return jsonify({"error": "Los parámetros de página deben ser números enteros"}), 400

    #1. Ejecutamos toda nuestra logica de POO
    lista_de_objetos_log = cargar_y_analizar_logs()
    total_logs = len(lista_de_objetos_log)

    start_index = (page - 1) * per_page
    end_index = start_index + per_page
    
    logs_para_esta_pagina = lista_de_objetos_log[start_index:end_index]
    #2. Convertimos nuestros objetos log en diccionarios
    # el navegador no entiende un objeto de python, pero sí un diccionario/JSON

    logs_como_diccionarios = []
    for log in logs_para_esta_pagina:
        logs_como_diccionarios.append({
            "timestamp": log.timestamp,
            "ip": log.ip,
            "mensaje": log.mensaje,
            "severidad": log.obtener_severidad() # llamamos al metodo del objeto
        })

    total_pages = (total_logs + per_page - 1) // per_page

    # 3. Devolvemos la lista de diccionarios como JSON
    # 'jsonify' convierte nuestra lista de Python en una respuesta JSON
    # que el navegador puede entender.

    return jsonify({
        "logs": logs_como_diccionarios,
        "total_pages": total_pages,
        "current_page": page,
        "total_logs": total_logs
    })

@app.route("/api/stats")
@login_required # Solo un usuario logueado puede ver las estadísticas
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
