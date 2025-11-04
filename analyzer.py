# Modulo: Analyzer.py
# Contiene toda la logica de analisis de logs

def obtener_severidad(log_a_procesar: dict) -> dict:

    """
    Analiza un unico log  en formato diccionario y DEVUELVE su severidad
    """
    # Extraemos el valor de la clave 'nivel' del diccionario
    nivel = log_a_procesar['nivel']

    if nivel == "ERROR":
        return "ALERTA"
    elif nivel == "WARN":
        return "AVISO"
    else:
        return "INFORMACION"

# --- Puedes añadir mas funciones aqui si lo deseas ---