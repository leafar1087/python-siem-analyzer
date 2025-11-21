# 🔒 SIEM Analyzer - Analizador de Logs de Seguridad

Un sistema completo de análisis de logs de seguridad (SIEM) construido con Flask que permite ingesta, almacenamiento, visualización y análisis inteligente de eventos de seguridad mediante Inteligencia Artificial.

## 📋 Tabla de Contenidos

- [Descripción](#descripción)
- [Características Principales](#características-principales)
- [Tecnologías Utilizadas](#tecnologías-utilizadas)
- [Requisitos Previos](#requisitos-previos)
- [Instalación](#instalación)
- [Configuración](#configuración)
- [Uso](#uso)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [API Endpoints](#api-endpoints)
- [Funcionalidades de IA](#funcionalidades-de-ia)
- [Simulador de Logs](#simulador-de-logs)
- [Seguridad](#seguridad)
- [Troubleshooting](#troubleshooting)
- [Contribuciones](#contribuciones)

## 📖 Descripción








**SIEM Analyzer** es una aplicación web completa diseñada para analizar y gestionar logs de seguridad en tiempo real. El sistema permite:

- **Ingesta de Logs**: Carga archivos JSON con eventos de seguridad
- **Almacenamiento Persistente**: Base de datos SQLite con deduplicación automática
- **Visualización en Tiempo Real**: Dashboard interactivo con gráficos y tablas
- **Análisis con IA**: Explicaciones automáticas de alertas usando modelos locales (Ollama)
- **Autenticación de Usuarios**: Sistema de login seguro con Flask-Login
- **Simulación de Eventos**: Herramienta para generar logs de prueba

## ✨ Características Principales

### 🔐 Seguridad (Capa 0)

- Sistema de autenticación con Flask-Login
- Contraseñas cifradas con Werkzeug
- Protección de rutas con decoradores `@login_required`
- Validación de formularios con WTForms

### 🎨 Nueva Interfaz de Usuario (v2.0)

- **Tema SB Admin 2**: Diseño moderno y profesional basado en Bootstrap 4
- **Layout Responsivo**: Barra lateral colapsable y barra superior de navegación
- **Modo Oscuro/Claro**: Estilos optimizados para legibilidad

### 📊 Visualización y Análisis

<img width="2941" height="1917" alt="image" src="https://github.com/user-attachments/assets/b8bf6cb4-ac43-4b21-bf5e-7dd819842f9b" />

- **Dashboard en Tiempo Real**: Actualización automática cada 5 segundos
- **Búsqueda Global**: Filtrado instantáneo de logs por IP, mensaje o nivel
- **Paginación Avanzada**:
  - Selector de tamaño de página (10, 25, 50, 100)
  - Navegación rápida (Primero, Anterior, Siguiente, Último)
- **Gráficos Interactivos**:
  - Gráfico de tarta para distribución por nivel
  - Gráfico de barras para Top 5 IPs más activas
- **Código de Colores**: Alertas visuales para niveles ERROR y WARN

### 🤖 Inteligencia Artificial

- Integración con **Ollama** (modelo phi3:mini)
- Análisis automático de alertas de seguridad
- Sugerencias de mitigación e investigación
- Interfaz modal para consultas de IA

  <img width="1448" height="794" alt="image" src="https://github.com/user-attachments/assets/e4186361-cb1e-4c8a-9532-89398d58e3bf" />
  

### 💾 Gestión de Datos

- **Deduplicación Automática**: Hash SHA-256 para evitar logs duplicados
- **Base de Datos SQLite**: Almacenamiento persistente y eficiente
- **Análisis con Pandas**: Estadísticas avanzadas sobre los logs
- **Carga Masiva**: Procesamiento de múltiples logs en un solo archivo JSON

## 🛠 Tecnologías Utilizadas

### Backend

- **Flask 2.x**: Framework web de Python
- **Flask-SQLAlchemy**: ORM para gestión de base de datos
- **Flask-Login**: Manejo de sesiones de usuario
- **Flask-WTF**: Protección CSRF y formularios
- **Werkzeug**: Utilidades de seguridad (hash de contraseñas)
- **Pandas**: Análisis de datos y estadísticas
- **Ollama**: Integración con modelos de IA locales

### Frontend

- **SB Admin 2**: Tema administrativo basado en Bootstrap 4
- **HTML5/CSS3**: Estructura y estilos personalizados
- **JavaScript (jQuery)**: Lógica del cliente y manipulación del DOM
- **Chart.js 2.9.4**: Visualización de gráficos (versión compatible con SB Admin 2)
- **Jinja2**: Motor de plantillas de Flask

### Base de Datos

- **SQLite**: Base de datos relacional ligera

## 📦 Requisitos Previos

Antes de instalar la aplicación, asegúrate de tener:

1. **Python 3.8+** instalado en tu sistema
2. **Ollama** instalado y corriendo (para funcionalidades de IA)
   - Descarga desde: https://ollama.ai
   - Modelo requerido: `phi3:mini`
   - Instalación del modelo: `ollama pull phi3:mini`

## 🚀 Instalación

### 1. Clonar o Descargar el Proyecto

```bash
cd /ruta/a/tu/proyecto
```

### 2. Crear un Entorno Virtual (Recomendado)

```bash
python3 -m venv .venv
source .venv/bin/activate  # En Windows: venv\Scripts\activate
```

### 3. Instalar Dependencias

Crea un archivo `requirements.txt` con las siguientes dependencias:

```txt
Flask==3.0.0
Flask-SQLAlchemy==3.1.1
Flask-Login==0.6.3
Flask-WTF==1.2.1
WTForms==3.1.1
Werkzeug==3.0.1
pandas==2.1.4
ollama==0.1.7
```

Luego instala:

```bash
pip install -r requirements.txt
```

### 4. Inicializar la Base de Datos

```bash
python3 -c "from app import app, db; app.app_context().push(); db.create_all()"
```

### 5. Crear un Usuario Administrador

```bash
python3 -c "
from app import app, db, User
with app.app_context():
    admin = User(username='admin')
    admin.set_password('admin123')
    db.session.add(admin)
    db.session.commit()
    print('Usuario admin creado con contraseña: admin123')
"
```

## ⚙️ Configuración

### Clave Secreta de Flask

**IMPORTANTE**: Cambia la clave secreta en `app.py` antes de usar en producción:

```python
# Genera una nueva clave secreta:
python3 -c 'import os; print(os.urandom(24).hex())'

# Reemplaza en app.py línea 38:
app.config['SECRET_KEY'] = 'TU_CLAVE_GENERADA_AQUI'
```

### Configuración de Ollama

Asegúrate de que Ollama esté corriendo:

```bash
# Verificar que Ollama está corriendo
ollama list

# Si no tienes el modelo phi3:mini, instálalo:
ollama pull phi3:mini
```

## 🎯 Uso

### Iniciar el Servidor

```bash
python3 app.py
```

El servidor estará disponible en: `http://localhost:5000`

### Acceder a la Aplicación

1. Abre tu navegador y ve a `http://localhost:5000`
2. Serás redirigido a la página de login
3. Inicia sesión con las credenciales creadas (por defecto: `admin` / `admin123`)

### Funcionalidades Disponibles

#### 📊 Dashboard Principal

- Visualiza logs en tiempo real
- Consulta estadísticas actualizadas
- Navega entre páginas de logs
- Analiza alertas con IA

#### 📤 Subir Logs

1. Ve a la sección "Subir Logs" en el menú
2. Selecciona un archivo JSON con el siguiente formato:

```json
[
  {
    "timestamp": "2024-01-15T10:30:00",
    "ip": "192.168.1.100",
    "nivel": "ERROR",
    "mensaje": "Fallo de autenticación"
  },
  {
    "timestamp": "2024-01-15T10:31:00",
    "ip": "10.0.0.5",
    "nivel": "WARN",
    "mensaje": "Intento de acceso a puerto 8080"
  }
]
```

3. Haz clic en "Subir"
4. El sistema procesará los logs y mostrará cuántos fueron añadidos y cuántos duplicados fueron ignorados

#### 🤖 Análisis con IA

1. En el dashboard, busca logs con nivel ERROR o WARN
2. Haz clic en el botón "🤖 IA" junto al log
3. Se abrirá un modal con la explicación generada por la IA
4. La IA proporcionará:
   - Explicación del evento en lenguaje simple
   - Sugerencia de acción de mitigación o investigación

## 📁 Estructura del Proyecto

python-siem-analyzer/
│
├── app.py # Aplicación principal Flask
├── simulador.py # Simulador de logs en tiempo real
├── debug_api.py # Script para probar endpoints de la API
├── debug_db.py # Script para inspeccionar la base de datos
├── requirements.txt # Dependencias del proyecto
├── README.md # Documentación del proyecto
│
├── instance/
│ └── users.db # Base de datos SQLite
│
├── static/
│ ├── css/
│ │ ├── sb-admin-2.min.css # Estilos del tema SB Admin 2
│ │ └── style.css # Estilos personalizados
│ └── js/
│ └── sb-admin-2.min.js # Scripts del tema SB Admin 2
│
└── templates/
├── base.html # Plantilla base con navegación
├── index.html # Dashboard principal
├── login.html # Página de inicio de sesión
└── upload.html # Página de carga de archivos

## 🔌 API Endpoints

### Autenticación

- `GET /login` - Página de inicio de sesión
- `POST /login` - Procesar credenciales
- `GET /logout` - Cerrar sesión

### Dashboard

- `GET /` - Dashboard principal (requiere autenticación)

### API REST

- `GET /api/logs?page=1&per_page=10` - Obtener logs paginados

  - Parámetros:
    - `page`: Número de página (default: 1)
    - `per_page`: Logs por página (default: 10)
  - Respuesta:
    ```json
    {
      "logs": [...],
      "current_page": 1,
      "total_pages": 5,
      "total_logs": 50
    }
    ```

- `GET /api/stats` - Obtener estadísticas

  - Respuesta:
    ```json
    {
      "total_logs": 150,
      "conteo_por_nivel": {
        "ERROR": 25,
        "WARN": 30,
        "INFO": 95
      },
      "top_5_ips": {
        "192.168.1.100": 45,
        "10.0.0.5": 32
      }
    }
    ```

- `POST /api/explain` - Analizar log con IA
  - Body:
    ```json
    {
      "mensaje": "Fallo de autenticación desde 192.168.1.100"
    }
    ```
  - Respuesta:
    ```json
    {
      "explicacion": "Este evento indica un intento fallido de autenticación..."
    }
    ```

### Carga de Archivos

- `GET /upload` - Página de carga de archivos
- `POST /upload` - Procesar archivo JSON subido

## 🤖 Funcionalidades de IA

### Modelo Utilizado

La aplicación utiliza **Ollama** con el modelo **phi3:mini**, un modelo ligero y eficiente que corre localmente.

### Prompt Engineering

El sistema utiliza ingeniería de prompts para obtener respuestas útiles:

- **Rol**: Analista experto en ciberseguridad (SOC Nivel 3)
- **Audiencia**: Analista junior (Nivel 1)
- **Tarea**: Explicar alertas y sugerir acciones

### Requisitos

- Ollama debe estar corriendo en el sistema
- El modelo `phi3:mini` debe estar descargado
- Conexión local (no requiere internet)

## 🎮 Simulador de Logs

El archivo `simulador.py` permite generar logs de prueba en tiempo real.

### Uso del Simulador

```bash
# En una terminal separada (mientras app.py está corriendo)
python3 simulador.py
```

### Características

- Genera logs aleatorios cada 2-5 segundos
- Simula diferentes niveles (INFO, WARN, ERROR)
- Usa IPs predefinidas para simular tráfico real
- Los logs se guardan directamente en la base de datos
- Presiona `Ctrl+C` para detener

### Tipos de Eventos Simulados

- **INFO**: Conexiones exitosas, backups, actualizaciones
- **WARN**: Intentos de acceso a puertos, alto uso de CPU
- **ERROR**: Fallos de autenticación, servicios caídos

## 🔒 Seguridad

### Medidas Implementadas

1. **Autenticación de Usuarios**

   - Contraseñas cifradas con hash bcrypt
   - Sesiones gestionadas por Flask-Login
   - Protección de rutas sensibles

2. **Validación de Entrada**

   - WTForms para validación de formularios
   - Sanitización de nombres de archivo
   - Validación de formato JSON

3. **Deduplicación**

   - Hash SHA-256 para prevenir logs duplicados
   - Índices en base de datos para búsquedas rápidas

4. **Protección CSRF**
   - Flask-WTF con tokens CSRF (configurable)

### Recomendaciones para Producción

- ⚠️ **Cambiar la SECRET_KEY** antes de desplegar
- ⚠️ Usar una base de datos más robusta (PostgreSQL, MySQL)
- ⚠️ Implementar HTTPS
- ⚠️ Configurar rate limiting
- ⚠️ Añadir logging de seguridad
- ⚠️ Implementar rotación de logs
- ⚠️ Usar variables de entorno para configuración sensible

## 🐛 Troubleshooting

### Problemas Comunes

#### 1. Error: "No se pudo contactar al asistente de IA"

**Solución**: Verifica que Ollama esté corriendo:

```bash
ollama list
ollama serve  # Si no está corriendo
```

#### 2. Error: "Usuario o contraseña incorrectos"

**Solución**: Crea un nuevo usuario o verifica las credenciales:

```bash
python3 -c "from app import app, db, User; app.app_context().push(); u = User(username='test'); u.set_password('test123'); db.session.add(u); db.session.commit()"
```

#### 3. Error: "El archivo JSON no es válido"

**Solución**: Verifica el formato del JSON. Debe ser un array de objetos con las claves: `timestamp`, `ip`, `nivel`, `mensaje`.

#### 4. La base de datos no se crea

**Solución**: Crea manualmente la carpeta `instance` y ejecuta:

```bash
python3 -c "from app import app, db; app.app_context().push(); db.create_all()"
```

#### 5. Los gráficos no se muestran

**Solución**: Verifica la conexión a internet (Chart.js se carga desde CDN) o descarga Chart.js localmente.

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Para contribuir:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📝 Licencia

Este proyecto es de código abierto y está disponible bajo la licencia MIT.

## 👤 Autor

Desarrollado por **Rafael Pérez**

- **LinkedIn:** [https://www.linkedin.com/in/rperezll/]
- **GitHub:** [https://github.com/leafar1087]

Desarrollado como proyecto educativo de análisis SIEM con Python y Flask.

**Nota**: Este es un proyecto educativo. Para uso en producción, implementa medidas de seguridad adicionales y realiza auditorías de seguridad.
