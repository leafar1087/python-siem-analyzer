#!/usr/bin/env python3
"""
Script para agregar campos de auditoría a la tabla Correlation.
Ejecutar: python3 migrate_audit_fields.py
"""

from app import app, db
from sqlalchemy import text

def migrate_audit_fields():
    """Agrega campos de auditoría a la tabla Correlation."""
    with app.app_context():
        print("Iniciando migración de campos de auditoría...")
        
        try:
            # Agregar columnas de auditoría
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE correlation ADD COLUMN resolved_by VARCHAR(100)"))
                print("✓ Columna 'resolved_by' agregada")
                
                conn.execute(text("ALTER TABLE correlation ADD COLUMN resolved_at DATETIME"))
                print("✓ Columna 'resolved_at' agregada")
                
                conn.execute(text("ALTER TABLE correlation ADD COLUMN resolved_from_ip VARCHAR(50)"))
                print("✓ Columna 'resolved_from_ip' agregada")
                
                conn.execute(text("ALTER TABLE correlation ADD COLUMN resolved_from_location VARCHAR(200)"))
                print("✓ Columna 'resolved_from_location' agregada")
                
                conn.execute(text("ALTER TABLE correlation ADD COLUMN notes TEXT"))
                print("✓ Columna 'notes' agregada")
                
                conn.commit()
            
            print("\n✓ Migración completada exitosamente")
            print("Campos de auditoría agregados a la tabla 'correlation'")
            
        except Exception as e:
            print(f"\n✗ Error durante la migración: {e}")
            print("Nota: Si las columnas ya existen, este error es esperado.")

if __name__ == "__main__":
    migrate_audit_fields()
