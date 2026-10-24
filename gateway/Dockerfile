FROM python:3.12-slim
RUN useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin gateway
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY policies ./policies
USER 10002
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080 8081
CMD ["python", "-m", "app.main"]
