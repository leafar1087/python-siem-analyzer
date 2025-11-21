import sqlite3
import os

db_path = 'instance/users.db'

print(f"--- DEBUGGING DATABASE: {db_path} ---")

if not os.path.exists(db_path):
    print(f"ERROR: Database file not found at {db_path}")
else:
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check Users
        cursor.execute("SELECT count(*) FROM user")
        user_count = cursor.fetchone()[0]
        print(f"Users found: {user_count}")
        
        # Check Logs
        cursor.execute("SELECT count(*) FROM log")
        log_count = cursor.fetchone()[0]
        print(f"Logs found: {log_count}")
        
        # Check for NULLs
        cursor.execute("SELECT count(*) FROM log WHERE severidad IS NULL OR nivel IS NULL OR mensaje IS NULL")
        null_count = cursor.fetchone()[0]
        print(f"Logs with NULL severidad/nivel/mensaje: {null_count}")
        
        if log_count > 0:
            print("First 3 logs:")
            cursor.execute("SELECT timestamp, nivel, severidad, mensaje FROM log ORDER BY id DESC LIMIT 3")
            for row in cursor.fetchall():
                print(f"- {row[0]} | {row[1]} | {row[2]} | {row[3]}")
        else:
            print("WARNING: No logs found in the database.")
            
        conn.close()
    except Exception as e:
        print(f"ERROR querying database: {e}")

print("--- END DEBUG ---")
