# models.py
# Modulo 3:programacion orientada a objetos
# Contiene las clases que modelan nuestros datos

class LogEvent:
    """
    Representa un unico evento de log como un objeto
    Contiene los datos del log como atributos
    """

    # --- CONSTRUCTOR ---
    def __init__(self, timestamp: str, nivel: str, mensaje: str, ip: str):

        print(f"Creando nuevo objeto LogEvent para IP: {ip}")

        # --- ATRIBUTOS ---
        # Asignamos los parametros recibidos a los atributos del objeto (usando self)
        self.timestamp = timestamp
        self.nivel = nivel
        self.mensaje = mensaje
        self.ip = ip
    
    # --- Métodos (Módulo 3.3) ---
    # ¡Convertimos la función en un método!
    # 1. Está INDENTADO dentro de la clase LogEvent.
    # 2. Su primer parámetro es AHORA 'self'.
    def obtener_severidad(self) -> str:

        """
        Analiza los atributos del propio objeto y DEVUELVE su severidad
        """
        # En lugar de de log_a_procesar.nivel, usamos self.nivel
        # self se refiere a este objeto en particular

        if self.nivel == "ERROR":
            return "ALERTA"
        elif self.nivel == "WARN":
            return "AVISO"
        else:
            return "INFORMACION"

    