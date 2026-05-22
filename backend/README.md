# ThreatWatch-AI - FastAPI Backend

This is the backend for **ThreatWatch-AI**, an AI-Powered Login Threat Detection and Risk Monitoring System.

## Technology Stack
- **Python**: 3.12
- **FastAPI**: Modern, fast web framework
- **SQLAlchemy**: 2.0 ORM with typed mappings
- **PostgreSQL**: Robust relational database
- **Alembic**: Database migrations
- **Pydantic**: Data validation and configuration settings
- **Uvicorn**: ASGI server

---

## Installation & Setup

1. **Create and Activate a Virtual Environment**
   ```bash
   python -m venv venv
   # On Windows (PowerShell):
   .\venv\Scripts\Activate.ps1
   # On macOS/Linux:
   source venv/bin/activate
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**
   - Copy `.env.example` to `.env`
   - Adjust the database connection details as necessary:
     ```env
     POSTGRES_USER=postgres
     POSTGRES_PASSWORD=your_password
     POSTGRES_DB=threatwatch_ai
     POSTGRES_HOST=localhost
     POSTGRES_PORT=5432
     DATABASE_URL=postgresql://postgres:your_password@localhost:5432/threatwatch_ai
     ```

4. **Run the Development Server**
   From the `backend` directory, run:
   ```bash
   python -m uvicorn app.main:app --reload
   ```
   The API will be available at [http://localhost:8000](http://localhost:8000).
   The API Documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs).

---

## Folder Structure

```
backend/
├── app/
│   ├── api/             # API Router layers
│   │   └── routes/      # Endpoint modules (auth, alerts, events, users)
│   ├── core/            # Configuration and Database configurations
│   ├── models/          # SQLAlchemy 2.0 declarative models
│   ├── schemas/         # Pydantic schemas (to be added in Phase 2)
│   ├── services/        # Business logic services (to be added in Phase 2)
│   ├── detectors/       # Heuristic engines (to be added in Phase 2)
│   ├── ml/              # ML components (to be added in Phase 2)
│   └── main.py          # FastAPI startup and route registration
├── requirements.txt     # List of dependencies
└── .env                 # Environment variables
```
