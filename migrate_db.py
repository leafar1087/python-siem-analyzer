#!/usr/bin/env python3
"""
Script para actualizar la base de datos con la tabla de Correlaciones.
Ejecutar: python3 migrate_db.py
"""

from app import app, db, Correlation

def migrate_database():
    """Crea las nuevas tablas en la base de datos."""
    with app.app_context():
        print("Iniciando migración de base de datos...")
        
        # Crear todas las tablas (solo creará las que no existan)
        db.create_all()
        
        print("✓ Tabla 'Correlation' creada exitosamente")
        print("✓ Migración completada")
        
        # Verificar que la tabla existe
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        print(f"\nTablas en la base de datos: {', '.join(tables)}")

if __name__ == "__main__":
    migrate_database()
