# simulador.py
# Este script se ejecuta en un terminal SEPARADO
# para simular la llegada de logs en vivo.

import time
import random
from datetime import datetime
# Importamos los componentes clave de nuestra app principal
from app import app, db, Log 
from sqlalchemy.exc import IntegrityError

# --- DATOS DE SIMULACIÓN ---
IPS_FALSAS = ['10.0.0.5', '192.168.1.1', '172.16.0.142', '10.0.0.207', '172.16.0.240', '192.168.1.100']

EVENTOS_FALSOS = {
    "INFO": [
        "Conexión exitosa",
        "Desconexión de usuario",
        "Servicio reiniciado",
        "Actualización de software iniciada",
        "Backup completado"
    ],
    "WARN": [
        "Intento de acceso a puerto 8080",
        "Uso de CPU alto (85%)",
        "Poco espacio en disco (15%)",
        "Login fallido (usuario no existe)"
    ],
    "ERROR": [
        "Fallo de autenticación",
        "Servicio caído: 'nginx'",
        "No se pudo conectar a la base de datos 'externa'",
        "Múltiples fallos de login desde la misma IP"
    ]
}
# --- FIN DE DATOS DE SIMULACIÓN ---

def crear_log_falso():
    """Crea y guarda un único log falso en la base de datos."""

    # 1. Elegimos un nivel aleatorio
    # Hacemos que INFO sea 3 veces más probable que WARN o ERROR
    nivel = random.choice(["INFO", "INFO", "INFO", "WARN", "ERROR"])

    # 2. Elegimos un mensaje basado en el nivel
    mensaje = random.choice(EVENTOS_FALSOS[nivel])

    # 3. Elegimos una IP aleatoria
    ip = random.choice(IPS_FALSAS)

    # 4. Creamos un timestamp actual (formato ISO)
    timestamp = datetime.now().isoformat(timespec='seconds')

    # 5. Asignamos severidad
    severidad = "INFO"
    if nivel == "ERROR":
        severidad = "ALERTA CRÍTICA"
    elif nivel == "WARN":
        severidad = "AVISO"

    # 6. Creamos el objeto Log (el hash se crea en el __init__)
    nuevo_log = Log(
        timestamp=timestamp,
        ip=ip,  # Asegúrate de que esto coincide con tu BD ('ip' o 'ip_origen')
        nivel=nivel,
        severidad=severidad,
        mensaje=mensaje
    )

    # 7. Intentamos guardarlo (con manejo de duplicados)
    try:
        db.session.add(nuevo_log)
        db.session.commit()
        print(f"[SIMULADOR] Nuevo log añadido: {nivel} desde {ip}")
    except IntegrityError:
        # ¡El hash ya existía! (muy improbable con timestamps, pero es bueno tenerlo)
        db.session.rollback()
        print("[SIMULADOR] Log duplicado detectado (ignorado).")
    except Exception as e:
        db.session.rollback()
        print(f"[SIMULADOR] Error al guardar en BD: {e}")

# --- FUNCIÓN PRINCIPAL ---
def iniciar_simulacion():
    print("--- Iniciando Simulador de Logs en Vivo ---")
    print("Ubicación de la BD:", app.config['SQLALCHEMY_DATABASE_URI'])
    print("Presiona Ctrl+C para detener.")

    # Usamos 'app.app_context()' para que este script
    # pueda "hablar" con la base de datos de Flask
    with app.app_context():
        while True:
            try:
                crear_log_falso()
                # Esperamos entre 2 y 5 segundos
                time.sleep(random.uniform(2, 5)) 
            except KeyboardInterrupt:
                print("\n--- Simulación detenida por el usuario ---")
                break

if __name__ == "__main__":
    iniciar_simulacion()