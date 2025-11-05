# models.py
# Modulo 3 y 4: clases y herencia

# --- CLASE PADRE, SUPERCLASE O BASE: LogEvent ---
class LogEvent:
    """
    Representa un unico evento de log como un objeto
    Contiene los datos del log como atributos y
    la logica de analisis como metodos
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

        if self.nivel == "ERROR":
            return "ALERTA"
        elif self.nivel == "WARN":
            return "AVISO"
        else:
            return "INFORMACION"


# --- CLASE HIJO O SUBCLASE [MODULO 4.1] ---
# Estas clases heredan TODO de LogEvent

class ErrorLogEvent(LogEvent):
    # Esta clase ahora tiene __init__ y obtener_severidad()
    # aunque no veamos el código aquí.
    # 'pass' es una palabra clave de Python que significa:
    # "No quiero añadir nada nuevo, esta clase está intencionalmente vacía".
    pass

class WarnLogEvent(LogEvent):
    # Esta clase tambien hereda de LogEvent
    pass

class InfoLogEvent(LogEvent):
    # Esta clase tambien hereda de LogEvent
    pass