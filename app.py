# app.py - Nuestro servidor web Flask
import ollama
import json, sys, pandas as pd, traceback, hashlib
# importamos el modulo render_template para poder renderizar nuestras plantillas HTML
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash

# ... (importaciones existentes)

# --- Nuevas importaciones para la Capa 0: Seguridad ---
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from flask_wtf.csrf import CSRFProtect


# --- FORMULARIO DE LOGIN (CAPA 0) ---

class LoginForm(FlaskForm):
    """Define los campos y validadores para el formulario de login."""
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar Sesión')


# 1. Creamos la aplicacion Flask
app = Flask(__name__)
CSRFProtect(app)

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
    
    return db.session.get(User, int(user_id))

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # el hash unico para deduplicacion
    # usampis index=true para que la busqueda sea mas rapida
    log_hash = db.Column(db.String(64), index=True, unique=True, nullable=False)
    timestamp = db.Column(db.String(100))
    ip = db.Column(db.String(100), index=True)
    nivel = db.Column(db.String(50))
    severidad = db.Column(db.String(50), index=True)
    mensaje = db.Column(db.Text)

    def __init__(self, timestamp, nivel, mensaje, ip, severidad):
        self.timestamp = timestamp
        self.nivel = nivel
        self.mensaje = mensaje
        self.ip = ip
        self.severidad = severidad

        self.log_hash = self._generar_hash()

    def _generar_hash(self):
        string_unico = f"{self.timestamp}-{self.ip}-{self.mensaje}"
        return hashlib.sha256(string_unico.encode()).hexdigest()
    
    def to_dict(self):
        """Convierte el objeto Log a diccionario para JSON."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "ip": self.ip,
            "nivel": self.nivel,
            "severidad": self.severidad,
            "mensaje": self.mensaje,
        }

class Correlation(db.Model):
    """Modelo para almacenar correlaciones de eventos detectadas."""
    id = db.Column(db.Integer, primary_key=True)
    correlation_type = db.Column(db.String(50), nullable=False)  # brute_force, port_scan, suspicious_ip, time_anomaly
    source_ip = db.Column(db.String(50), index=True, nullable=False)
    event_count = db.Column(db.Integer, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    first_seen = db.Column(db.DateTime, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.Text, nullable=False)
    related_log_ids = db.Column(db.Text)  # JSON array of log IDs
    status = db.Column(db.String(20), default='ACTIVE')  # ACTIVE, RESOLVED, FALSE_POSITIVE
    created_at = db.Column(db.DateTime, default=db.func.now())
    
    # Audit trail fields
    resolved_by = db.Column(db.String(100))  # Username who resolved
    resolved_at = db.Column(db.DateTime)  # When it was resolved
    resolved_from_ip = db.Column(db.String(50))  # IP address of resolver
    resolved_from_location = db.Column(db.String(200))  # Hostname/location
    notes = db.Column(db.Text)  # Analyst notes
    
    def to_dict(self):
        """Convierte el objeto a diccionario para JSON."""
        return {
            'id': self.id,
            'correlation_type': self.correlation_type,
            'source_ip': self.source_ip,
            'event_count': self.event_count,
            'severity': self.severity,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'description': self.description,
            'related_log_ids': json.loads(self.related_log_ids) if self.related_log_ids else [],
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'resolved_by': self.resolved_by,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolved_from_ip': self.resolved_from_ip,
            'resolved_from_location': self.resolved_from_location,
            'notes': self.notes
        }




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
    Usa Pandas para leer la BASE DE DATOS y generar estadísticas.
    """
    try:
        # 1. Creamos una consulta de SQLAlchemy para seleccionar todos los logs
        query = Log.query
        
        # 2. ¡La nueva magia! Pandas lee la consulta de SQLAlchemy
        # 'db.engine' es el motor de conexión a nuestra BD (users.db)
        df = pd.read_sql_query(query.statement, db.engine)

        # 3. Comprobamos si el DataFrame está vacío
        if df.empty:
            return {
                "total_logs": 0,
                "conteo_por_nivel": {},
                "top_5_ips": {}
            }

        # 4. Hacemos el análisis (¡ESTO ES IDÉNTICO A ANTES!)
        # (Asegúrate de que 'ip' coincida con tu columna)
        top_ips = df['ip'].value_counts().nlargest(5).to_dict()
        conteo_niveles = df['nivel'].value_counts().to_dict()
        
        # 5. Preparamos la respuesta de éxito
        stats = {
            "total_logs": int(len(df)),
            "conteo_por_nivel": conteo_niveles,
            "top_5_ips": top_ips
        }
        return stats

    except Exception as e:
        db.session.rollback()
        # Este error ahora sí debería ser visible si algo más falla
        print(f"Error al generar estadísticas con Pandas: {e}")
        return {"error": str(e)}

def parsear_log_json(archivo_subido):
    try:
        contenido_texto = archivo_subido.read().decode('utf-8')
        logs_crudos = json.loads(contenido_texto)
        if not isinstance(logs_crudos, list):
            return None, "El JSON debe ser una lista de logs"
        return logs_crudos, None
    except Exception as e:
        print(f"[ERROR] Error al parsear el archivo JSON: {e}")
        return None, f"Error al leer el archivo JSON: {str(e)}"


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
@login_required 
def get_logs():
    
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        print(f"[DEBUG] /api/logs called. Page: {page}, PerPage: {per_page}") # DEBUG
    except ValueError:
        return jsonify({"error": "Parámetros 'page' y 'per_page' deben ser números."}), 400

    # --- ¡LÓGICA DE LECTURA ACTUALIZADA! ---
    # Ya no leemos de 'logs.json', ¡consultamos la BD!
    
    # 1. Obtenemos el término de búsqueda
    search_query = request.args.get('search', '', type=str)

    # 2. Construimos la consulta base
    query = Log.query

    # 3. Aplicamos filtro si hay búsqueda
    if search_query:
        search_term = f"%{search_query}%"
        # Filtramos por IP, Mensaje, Severidad o Timestamp
        # Usamos 'ilike' para búsqueda insensible a mayúsculas/minúsculas
        query = query.filter(
            db.or_(
                Log.ip.ilike(search_term),
                Log.mensaje.ilike(search_term),
                Log.severidad.ilike(search_term),
                Log.timestamp.ilike(search_term)
            )
        )

    # 4. Obtenemos el objeto de paginación de SQLAlchemy
    # '.order_by(Log.timestamp.desc())' muestra los logs más nuevos primero.
    # '.paginate()' es la magia que maneja todo por nosotros.
    try:
        paginacion = query.order_by(Log.timestamp.desc()).paginate(
            page=page, 
            per_page=per_page, 
            error_out=False # No da error 404 si la página está vacía
        )
    except Exception as e:
        db.session.rollback()
        print(f"Error al consultar logs: {e}")
        return jsonify({"error": "Error interno al consultar la base de datos."}), 500

    # 2. 'paginacion.items' contiene la lista de objetos Log para esta página
    logs_para_esta_pagina = paginacion.items
    
    # 3. Convertimos los objetos Log a diccionarios
    logs_como_diccionarios = [log.to_dict() for log in logs_para_esta_pagina]
    
    # 4. Devolvemos el JSON con la info de paginación del objeto
    print(f"[DEBUG] Found {len(logs_como_diccionarios)} logs for this page. Total: {paginacion.total}") # DEBUG
    return jsonify({
        'logs': logs_como_diccionarios,
        'current_page': paginacion.page,
        'total_pages': paginacion.pages,
        'total_logs': paginacion.total
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

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_logs():
    # Si el método es POST, significa que el usuario ha subido el formulario
    if request.method == 'POST':
        
        # 1. Comprobamos que el formulario tenga una parte 'log_file'
        if 'log_file' not in request.files:
            flash('Error: No se encontró la parte del archivo.', 'danger')
            return redirect(request.url)
        
        file = request.files['log_file']
        
        # 2. Comprobamos que el usuario haya seleccionado un archivo
        if file.filename == '':
            flash('Error: No se seleccionó ningún archivo.', 'danger')
            return redirect(request.url)
            
        if file:
            # 3. Validamos el nombre del archivo (opcional pero seguro)
            filename = secure_filename(file.filename)
            
            # --- ¡AQUÍ EMPIEZA LA INGESTA! ---
            if filename.endswith('.json'):
                logs_crudos, error = parsear_log_json(file)
                if error:
                    flash(f'Error: {error}', 'danger')
                    return redirect(request.url)
                
                contador_nuevos = 0
                contador_duplicados = 0
                
                # 4. Iteramos sobre los logs del archivo
                for log_dict in logs_crudos:
                    try:
                        # 5. Creamos el objeto Log
                        # (Aquí asumimos que nuestro JSON tiene las mismas claves)
                        # Nota: Nuestra clase LogEvent/ErrorLogEvent ya no se usa aquí
                        # Estamos creando el objeto Log de la BD directamente.
                        
                        # (Vamos a simular la lógica de severidad aquí mismo)
                        nivel = log_dict.get('nivel', 'INFO')
                        severidad = "INFO"
                        if nivel == "ERROR":
                            severidad = "ALERTA CRÍTICA"
                        elif nivel == "WARN":
                            severidad = "AVISO"
                        
                        nuevo_log = Log(
                            timestamp=log_dict.get('timestamp'),
                            ip=log_dict.get('ip'),
                            nivel=nivel,
                            severidad=severidad,
                            mensaje=log_dict.get('mensaje')
                        )
                        # (El hash se crea automáticamente en el __init__)
                        
                        # 6. Intentamos añadirlo a la BD
                        db.session.add(nuevo_log)
                        db.session.commit() # Hacemos commit por cada uno
                        contador_nuevos += 1
                        
                    except IntegrityError:
                        # 7. ¡DEDUPLICACIÓN!
                        # Esto falla si el hash (log_hash) ya existe.
                        # "Deshacemos" la transacción fallida
                        db.session.rollback()
                        contador_duplicados += 1
                    except Exception as e:
                        # Otro error (ej. datos faltantes)
                        db.session.rollback()
                        print(f"Error al procesar log: {e}")

                flash(f'¡Archivo procesado! {contador_nuevos} logs nuevos añadidos, {contador_duplicados} duplicados ignorados.', 'success')
                return redirect(url_for('upload_logs'))

            else:
                flash('Error: Formato de archivo no soportado. Por favor, suba un .json.', 'danger')
                return redirect(request.url)

    # Si el método es GET, solo mostramos la página de subida
    return render_template('upload.html')

# --- ENDPOINT DE IA (MÓDULO 5) ---


@app.route('/api/explain', methods=['POST'])
@login_required
def explain_log():
    """
    Recibe un mensaje de log y devuelve una explicación
    generada por el LLM local (Ollama).
    """
    
    # 1. Obtenemos el log del frontend
    # Usamos POST, así que los datos vienen en el 'body' como JSON
    data = request.get_json()
    if not data or 'mensaje' not in data:
        return jsonify({"error": "No se proporcionó ningún mensaje de log."}), 400
        
    log_message = data.get('mensaje')

    # 2. Ingeniería de Prompts (La nueva versión limpia)
    # Le damos un "rol" de sistema con instrucciones claras y un formato.
    system_prompt = """
    Eres un analista de ciberseguridad (SOC Nivel 3) experto.
    Tu trabajo es explicar alertas a un analista junior.
    Sé profesional, claro y muy conciso. No uses saludos ni despedidas.
    Responde SIEMPRE en español.

    Tu respuesta debe tener este formato EXACTO:
    
    EXPLICACIÓN: [Tu explicación de 1-2 frases aquí]
    
    ACCIÓN INMEDIATA: [Tu sugerencia de 1-2 acciones aquí]
    """
    
    # Esta es la "pregunta" que le hacemos
    user_prompt = f"Analiza esta alerta de log: '{log_message}'"

    try:
        # 3. Llamamos a Ollama (que corre en local)
        print(f"[IA] Consultando a phi3:mini sobre: '{log_message}'")
        
        response = ollama.chat(
            model='phi3:mini', # ¡Usamos el modelo ligero!
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_prompt}
            ],
            stream=False # Queremos la respuesta completa
        )
        
        # 4. Extraemos y devolvemos la respuesta
        explicacion = response['message']['content']
        print(f"[IA] Respuesta recibida: {explicacion}")
        
        return jsonify({'explicacion': explicacion})

    except Exception as e:
        # Esto fallará si el servicio 'Ollama' no está corriendo en tu Mac
        print(f"[IA] ERROR: No se pudo conectar al servicio de Ollama. {e}")
        return jsonify({"error": "No se pudo contactar al asistente de IA. ¿Está Ollama corriendo?"}), 500


# ==================== CORRELACIÓN DE EVENTOS ====================

from datetime import datetime, timedelta

def analyze_correlations():
    """
    Motor de correlación que analiza logs recientes y detecta patrones.
    Retorna lista de correlaciones detectadas.
    """
    correlations = []
    
    # Analizamos logs de las últimas 24 horas
    time_threshold = datetime.now() - timedelta(hours=24)
    
    # 1. DETECCIÓN DE FUERZA BRUTA
    brute_force = detect_brute_force(time_threshold)
    correlations.extend(brute_force)
    
    # 2. DETECCIÓN DE ESCANEO DE PUERTOS
    port_scans = detect_port_scanning(time_threshold)
    correlations.extend(port_scans)
    
    # 3. DETECCIÓN DE IP SOSPECHOSA
    suspicious_ips = detect_suspicious_ip_activity(time_threshold)
    correlations.extend(suspicious_ips)
    
    # 4. DETECCIÓN DE ANOMALÍAS TEMPORALES
    time_anomalies = detect_time_anomalies(time_threshold)
    correlations.extend(time_anomalies)
    
    return correlations

def detect_brute_force(time_threshold):
    """Detecta múltiples intentos fallidos de autenticación desde la misma IP."""
    correlations = []
    
    # Buscamos logs con palabras clave de fallo de autenticación
    keywords = ['fallo', 'fallido', 'failed', 'authentication', 'autenticación', 'login']
    
    # Query para agrupar por IP
    query = db.session.query(
        Log.ip,
        db.func.count(Log.id).label('count'),
        db.func.min(Log.timestamp).label('first_seen'),
        db.func.max(Log.timestamp).label('last_seen'),
        db.func.group_concat(Log.id).label('log_ids')
    ).filter(
        db.or_(*[Log.mensaje.like(f'%{kw}%') for kw in keywords]),
        Log.nivel.in_(['ERROR', 'WARN'])
    ).group_by(Log.ip).having(db.func.count(Log.id) >= 5)
    
    for result in query.all():
        severity = 'CRITICAL' if result.count >= 10 else 'HIGH' if result.count >= 7 else 'MEDIUM'
        
        correlations.append({
            'type': 'brute_force',
            'ip': result.ip,
            'count': result.count,
            'severity': severity,
            'first_seen': result.first_seen,
            'last_seen': result.last_seen,
            'description': f'Detectados {result.count} intentos fallidos de autenticación desde {result.ip}',
            'log_ids': result.log_ids.split(',') if result.log_ids else []
        })
    
    return correlations

def detect_port_scanning(time_threshold):
    """Detecta acceso a múltiples puertos desde la misma IP."""
    correlations = []
    
    # Buscamos logs con referencias a puertos
    keywords = ['puerto', 'port', '8080', '443', '22', '3306', '5432']
    
    query = db.session.query(
        Log.ip,
        db.func.count(db.func.distinct(Log.mensaje)).label('unique_ports'),
        db.func.count(Log.id).label('total_events'),
        db.func.min(Log.timestamp).label('first_seen'),
        db.func.max(Log.timestamp).label('last_seen'),
        db.func.group_concat(Log.id).label('log_ids')
    ).filter(
        db.or_(*[Log.mensaje.like(f'%{kw}%') for kw in keywords])
    ).group_by(Log.ip).having(db.func.count(db.func.distinct(Log.mensaje)) >= 5)
    
    for result in query.all():
        severity = 'HIGH' if result.unique_ports >= 10 else 'MEDIUM'
        
        correlations.append({
            'type': 'port_scan',
            'ip': result.ip,
            'count': result.total_events,
            'severity': severity,
            'first_seen': result.first_seen,
            'last_seen': result.last_seen,
            'description': f'Posible escaneo de puertos desde {result.ip}: {result.unique_ports} puertos diferentes accedidos',
            'log_ids': result.log_ids.split(',') if result.log_ids else []
        })
    
    return correlations

def detect_suspicious_ip_activity(time_threshold):
    """Detecta IPs con actividad anormalmente alta."""
    correlations = []
    
    query = db.session.query(
        Log.ip,
        db.func.count(Log.id).label('count'),
        db.func.min(Log.timestamp).label('first_seen'),
        db.func.max(Log.timestamp).label('last_seen'),
        db.func.group_concat(Log.id).label('log_ids')
    ).filter(
        Log.nivel.in_(['ERROR', 'WARN'])
    ).group_by(Log.ip).having(db.func.count(Log.id) >= 15)
    
    for result in query.all():
        severity = 'HIGH' if result.count >= 30 else 'MEDIUM'
        
        correlations.append({
            'type': 'suspicious_ip',
            'ip': result.ip,
            'count': result.count,
            'severity': severity,
            'first_seen': result.first_seen,
            'last_seen': result.last_seen,
            'description': f'Actividad sospechosa desde {result.ip}: {result.count} eventos de ERROR/WARN',
            'log_ids': result.log_ids.split(',') if result.log_ids else []
        })
    
    return correlations

def detect_time_anomalies(time_threshold):
    """Detecta actividad fuera de horario normal (00:00-06:00)."""
    correlations = []
    
    # Nota: Esto es una implementación simplificada
    # En producción, necesitarías parsear los timestamps correctamente
    
    query = db.session.query(
        Log.ip,
        db.func.count(Log.id).label('count'),
        db.func.min(Log.timestamp).label('first_seen'),
        db.func.max(Log.timestamp).label('last_seen'),
        db.func.group_concat(Log.id).label('log_ids')
    ).filter(
        Log.nivel.in_(['ERROR', 'WARN'])
    ).group_by(Log.ip).having(db.func.count(Log.id) >= 10)
    
    for result in query.all():
        # Simplificación: marcamos como anomalía temporal si hay muchos eventos
        if result.count >= 20:
            correlations.append({
                'type': 'time_anomaly',
                'ip': result.ip,
                'count': result.count,
                'severity': 'MEDIUM',
                'first_seen': result.first_seen,
                'last_seen': result.last_seen,
                'description': f'Volumen anormal de actividad desde {result.ip}: {result.count} eventos en periodo corto',
                'log_ids': result.log_ids.split(',') if result.log_ids else []
            })
    
    return correlations

def save_correlation(corr_data):
    """Guarda una correlación en la base de datos, evitando duplicados."""
    try:
        # Verificar si ya existe una correlación similar activa
        existing = Correlation.query.filter_by(
            correlation_type=corr_data['type'],
            source_ip=corr_data['ip'],
            status='ACTIVE'
        ).first()
        
        if existing:
            # Actualizar la existente
            existing.event_count = corr_data['count']
            existing.last_seen = datetime.fromisoformat(corr_data['last_seen']) if isinstance(corr_data['last_seen'], str) else corr_data['last_seen']
            existing.severity = corr_data['severity']
            existing.related_log_ids = json.dumps(corr_data['log_ids'])
        else:
            # Crear nueva
            new_corr = Correlation(
                correlation_type=corr_data['type'],
                source_ip=corr_data['ip'],
                event_count=corr_data['count'],
                severity=corr_data['severity'],
                first_seen=datetime.fromisoformat(corr_data['first_seen']) if isinstance(corr_data['first_seen'], str) else corr_data['first_seen'],
                last_seen=datetime.fromisoformat(corr_data['last_seen']) if isinstance(corr_data['last_seen'], str) else corr_data['last_seen'],
                description=corr_data['description'],
                related_log_ids=json.dumps(corr_data['log_ids'])
            )
            db.session.add(new_corr)
        
        db.session.commit()
        return True
    except Exception as e:
        print(f"Error guardando correlación: {e}")
        db.session.rollback()
        return False

# ==================== ENDPOINTS DE CORRELACIÓN ====================

@app.route('/correlations')
@login_required
def correlations():
    """Página de correlaciones de eventos."""
    return render_template('correlation.html')

@app.route('/api/correlations')
@login_required
def get_correlations():
    """API: Obtiene todas las correlaciones detectadas."""
    try:
        # Parámetros de filtrado
        status = request.args.get('status', 'ACTIVE')
        severity = request.args.get('severity', None)
        corr_type = request.args.get('type', None)
        
        query = Correlation.query
        
        if status and status != 'ALL':
            query = query.filter_by(status=status)
        if severity:
            query = query.filter_by(severity=severity)
        if corr_type:
            query = query.filter_by(correlation_type=corr_type)
        
        correlations = query.order_by(Correlation.created_at.desc()).all()
        
        return jsonify({
            'correlations': [c.to_dict() for c in correlations],
            'total': len(correlations)
        })
    except Exception as e:
        print(f"Error obteniendo correlaciones: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/correlations/analyze', methods=['POST'])
@login_required
def trigger_correlation_analysis():
    """API: Ejecuta el análisis de correlación manualmente."""
    try:
        correlations = analyze_correlations()
        
        # Guardar correlaciones detectadas
        saved_count = 0
        for corr in correlations:
            if save_correlation(corr):
                saved_count += 1
        
        return jsonify({
            'message': f'Análisis completado. {saved_count} correlaciones detectadas/actualizadas.',
            'detected': len(correlations),
            'saved': saved_count
        })
    except Exception as e:
        print(f"Error en análisis de correlación: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/correlations/summary')
@login_required
def get_correlations_summary():
    """API: Obtiene resumen de correlaciones para el dashboard."""
    try:
        # Obtener correlaciones activas
        active_correlations = Correlation.query.filter_by(status='ACTIVE').all()
        
        # Contar por severidad
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for corr in active_correlations:
            severity_counts[corr.severity] = severity_counts.get(corr.severity, 0) + 1
        
        # Obtener top 5 más recientes (ordenadas por severidad y fecha)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        top_correlations = sorted(
            active_correlations,
            key=lambda x: (severity_order.get(x.severity, 4), x.created_at),
            reverse=False
        )[:5]
        
        return jsonify({
            'total_active': len(active_correlations),
            'severity_counts': severity_counts,
            'top_correlations': [c.to_dict() for c in top_correlations],
            'has_critical': severity_counts['CRITICAL'] > 0
        })
    except Exception as e:
        print(f"Error obteniendo resumen de correlaciones: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/correlations/<int:corr_id>/status', methods=['PUT'])
@login_required
def update_correlation_status(corr_id):
    """API: Actualiza el estado de una correlación con información de auditoría."""
    try:
        data = request.get_json()
        new_status = data.get('status')
        notes = data.get('notes', '')
        
        if new_status not in ['ACTIVE', 'RESOLVED', 'FALSE_POSITIVE']:
            return jsonify({'error': 'Estado inválido'}), 400
        
        correlation = Correlation.query.get(corr_id)
        if not correlation:
            return jsonify({'error': 'Correlación no encontrada'}), 404
        
        # Actualizar estado
        correlation.status = new_status
        
        # Capturar información de auditoría si se está resolviendo
        if new_status in ['RESOLVED', 'FALSE_POSITIVE']:
            from datetime import datetime
            import socket
            
            correlation.resolved_by = current_user.username
            correlation.resolved_at = datetime.now()
            correlation.resolved_from_ip = request.remote_addr
            
            # Intentar obtener hostname
            try:
                correlation.resolved_from_location = socket.gethostbyaddr(request.remote_addr)[0]
            except:
                correlation.resolved_from_location = request.remote_addr
            
            correlation.notes = notes
        
        db.session.commit()
        
        return jsonify({'message': 'Estado actualizado', 'correlation': correlation.to_dict()})
    except Exception as e:
        print(f"Error actualizando estado: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# INICIO DEL SERVIDOR

if __name__ == "__main__":
    # debug=True: nos permite ver los errores en el navegador y el servidor se reinicia automaticamente
    # port=5000: el puerto en el que se ejecutara el servidor
    app.run(debug=True, port=5000) 
