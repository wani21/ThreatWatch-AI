# ThreatWatch-AI
### AI-Powered Login Threat Detection & Risk Monitoring System

ThreatWatch-AI is a production-grade, real-time security dashboard designed to identify and thwart suspicious user logins using heuristic checks and behavioral profile modeling. 

This repository houses the complete project foundation: a FastAPI backend powered by SQLAlchemy 2.0 and PostgreSQL, along with a clean skeleton structure for a React + TypeScript frontend.

---

## Technical Stack Overview

* **Backend**: Python 3.12, FastAPI, SQLAlchemy 2.0, PostgreSQL, Alembic, Pydantic, Uvicorn.
* **Frontend**: React + TypeScript (Structure skeleton ready for development).

---

## Setup & Database Configuration Guide

### 1. PostgreSQL Setup Instructions

ThreatWatch-AI relies on a local or remote PostgreSQL instance. Follow these steps to configure your database:

#### Windows Installation:
1. Download the PostgreSQL Installer from the [EnterpriseDB Downloads Page](https://www.enterprisedb.com/downloads/postgres-postgresql-downloads). Select Version 15 or newer.
2. Run the installation wizard. Ensure **PostgreSQL Server**, **pgAdmin 4**, and **Command Line Tools** are selected.
3. During setup, configure a password for the default `postgres` superuser (e.g., `postgres`) and leave the port as `5432`.
4. Ensure the PostgreSQL service is running. Open your terminal or Command Prompt and run:
   ```cmd
   net start postgresql-x64-16
   ```

#### Creating the Database:
Open a command shell or `psql` and run:
```sql
-- Connect as postgres superuser
CREATE DATABASE threatwatch_ai;
```
Or use the CLI command:
```bash
createdb -U postgres threatwatch_ai
```

---

### 2. Alembic Initialization Instructions

Alembic provides a clean database schema migration history. Since our models are fully defined using SQLAlchemy 2.0 `Base` metadata, follow these instructions to initialize and run database migrations:

1. **Initialize Alembic in the Backend Project Folder**
   Navigate to the `backend/` directory in your terminal and run:
   ```bash
   cd backend
   alembic init alembic
   ```
   This generates an `alembic.ini` file and an `alembic/` subdirectory.

2. **Configure Alembic to read `DATABASE_URL` from Environment Variables**
   Open `backend/alembic/env.py` and modify it to load settings from our `Settings` class:
   ```python
   # Add backend directory to path
   import sys
   import os
   sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

   # Import our database settings and Base metadata
   from app.core.config import settings
   from app.models import Base

   # Set target metadata
   target_metadata = Base.metadata

   # Inside run_migrations_offline() and run_migrations_online(), retrieve URL from settings:
   # url = settings.DATABASE_URL
   ```
   *Alternative simplified configuration in `alembic.ini`:*
   Change the `sqlalchemy.url` line in `backend/alembic.ini` to match your Postgres URL:
   ```ini
   sqlalchemy.url = postgresql://postgres:postgres@localhost:5432/threatwatch_ai
   ```

3. **Generate the First Migration Revision (Autogenerate)**
   Alembic will automatically inspect our models inside `app/models/` and match them against the empty database:
   ```bash
   alembic revision --autogenerate -m "Initial schema setup"
   ```

4. **Apply Migrations to the Database**
   Run the following to apply the generated migrations and build your tables in PostgreSQL:
   ```bash
   alembic upgrade head
   ```

---

### 3. Running the FastAPI Application

1. Make sure you are inside the `backend` folder and your virtual environment is active.
2. Verify you have a `.env` configured with the correct `DATABASE_URL`.
3. Launch Uvicorn:
   ```bash
   python -m uvicorn app.main:app --reload
   ```
4. Access the API documentation at [http://localhost:8000/docs](http://localhost:8000/docs).
5. Verify application health by checking the `/health` endpoint:
   ```bash
   curl http://localhost:8000/health
   ```
   Response:
   ```json
   {
     "status": "healthy",
     "app_name": "ThreatWatch-AI",
     "environment": "development",
     "version": "1.0.0"
   }
   ```
