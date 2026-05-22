#!/usr/bin/env python
import sys
import os
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Inject the backend directory into the Python Path to resolve imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.config import settings

def main():
    print("[*] Connecting to default 'postgres' database to check/create the target database...")
    
    user = settings.POSTGRES_USER
    password = settings.POSTGRES_PASSWORD
    host = settings.POSTGRES_HOST
    port = settings.POSTGRES_PORT
    target_db = settings.POSTGRES_DB

    # Parse DATABASE_URL if available to match the credentials used by SQLAlchemy
    db_url = settings.DATABASE_URL
    if db_url and db_url.startswith("postgresql://"):
        try:
            stripped = db_url[len("postgresql://"):]
            if "@" in stripped:
                credentials, host_port_db = stripped.split("@", 1)
                if ":" in credentials:
                    user, password = credentials.split(":", 1)
                else:
                    user = credentials
                
                if "/" in host_port_db:
                    host_port, _ = host_port_db.split("/", 1)
                else:
                    host_port = host_port_db
                
                if ":" in host_port:
                    host, port = host_port.split(":", 1)
                    port = int(port)
                else:
                    host = host_port
        except Exception as e:
            print(f"[!] Error parsing DATABASE_URL, falling back to individual settings: {e}")

    print(f"    - Connection Host: {host}:{port}")
    print(f"    - Username: {user}")
    print(f"    - Target Database: {target_db}")

    try:
        # Connect to the default 'postgres' database which always exists
        conn = psycopg2.connect(
            dbname="postgres",
            user=user,
            password=password,
            host=host,
            port=port
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Check if the target database exists
        cursor.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s;", (target_db,))
        exists = cursor.fetchone()
        
        if not exists:
            print(f"[*] Database '{target_db}' does not exist. Creating it...")
            cursor.execute(f'CREATE DATABASE "{target_db}";')
            print(f"[+] Database '{target_db}' created successfully!")
        else:
            print(f"[+] Database '{target_db}' already exists.")
            
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[!] Error occurred: {e}")
        print("\nPlease verify:")
        print("1. Your PostgreSQL server is running locally.")
        print("2. The username, password, and port in your .env are correct.")
        sys.exit(1)

if __name__ == "__main__":
    main()
