# models.py
# Modulo 3:programacion orientada a objetos
# Contiene las clases que modelan nuestros datos

class LogEvent:
    """
    Representa un unico evento de log como un objeto
    Contiene los datos del log como atributos
    """

    def __init__(self, timestamp: str, nivel: str, mensaje: str, ip: str):

        print(f"Creando nuevo objeto LogEvent para IP: {ip}")

        # --- ATRIBUTOS ---
        # Asignamos los parametros recibidos a los atributos del objeto (usando self)
        self.timestamp = timestamp
        self.nivel = nivel
        self.mensaje = mensaje
        self.ip = ip

    