# Modulo: Analyzer.py
# Contiene toda la logica de analisis de logs

def obtener_severidad(log_a_procesar: LogEvent) -> str:

    """
    Analiza un unico objeto LogEvent y DEVUELVE su severidad
    """
    # En lugar de claves de diccionario ['nivel'], usamos atributos de objeto '.nivel'
    nivel_log = log_a_procesar.nivel

    if nivel_log == "ERROR":
        return "ALERTA"
    elif nivel_log == "WARN":
        return "AVISO"
    else:
        return "INFORMACION"

# --- Puedes añadir mas funciones aqui si lo deseas ---