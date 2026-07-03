# Stage 1: Build frontend
FROM node:20-alpine AS frontend-build
WORKDIR /frontend
COPY webapp/frontend/package*.json ./
RUN npm ci
COPY webapp/frontend/ .
RUN npm run build

# Stage 2: Backend application
FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY webapp/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application code
COPY webapp/backend/app ./app
COPY webapp/backend/seed_checklist.json ./seed_checklist.json

# Copy src package (required for PDF-to-CSV conversion)
COPY src ./src

# Copy built frontend static files
COPY --from=frontend-build /frontend/dist ./static

RUN mkdir -p /app/storage /app/data

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
