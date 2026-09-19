# MailTrace AI Backend — Render Deployment

## Recommended setup

Deploy this folder as a **Python Web Service** (not Docker unless you specifically want Docker).

### If this is a monorepo

Example:

    project/
      frontend/
      backend/

In Render set:

- Root Directory: `backend`
- Runtime: `Python 3`
- Build Command: `pip install -r requirements.txt`
- Start Command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Health Check Path: `/health`

### Database

Create a Render PostgreSQL database and set:

    DATABASE_URL=<Render Postgres connection string>

The backend automatically switches from local SQLite to PostgreSQL when `DATABASE_URL` is present.

Do **not** deploy the bundled local `data/mailtrace.db`; it is intentionally excluded from this deployment package.

### Environment variables

Minimum:

    DATABASE_URL=...
    LLM_ENABLED=false
    LLM_PROVIDER=mock
    RATE_LIMIT_ENABLED=true
    CORS_ORIGINS=https://YOUR-FRONTEND-DOMAIN

Optional:

    LLM_PROVIDER=gemini
    LLM_MODEL=gemini-1.5-flash
    GEMINI_API_KEY=...
    IP_INTELLIGENCE_PROVIDER=ipapi
    IPAPI_KEY=...
    GEOLOCATION_REQUIRE_API_KEY=false

Never commit API keys or `.env` files.

## Verify after deployment

Open:

    https://YOUR-BACKEND.onrender.com/health

Expected response:

    {"status":"ok","service":"cybersecurity-email-parser","database":"ok"}

Then open:

    https://YOUR-BACKEND.onrender.com/docs

## Important storage note

Render web-service filesystems are ephemeral by default. Runtime uploads and local EML files should not be treated as permanent storage. PostgreSQL is used for relational data; if uploaded evidence must survive restarts/redeploys, move evidence storage to object storage or use a paid Render persistent disk.
