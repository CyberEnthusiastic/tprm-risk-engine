FROM python:3.11-slim
WORKDIR /app
COPY . .
ENTRYPOINT ["python", "risk_engine.py"]
