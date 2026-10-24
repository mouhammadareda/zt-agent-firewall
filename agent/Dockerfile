FROM python:3.12-slim
# no extra packages: the agent only needs the Python standard library
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin agent
WORKDIR /app
COPY agent.py tools_direct.py ./
USER 10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# the container idles; tasks are started with: docker compose exec agent python agent.py "<task>"
CMD ["python", "-c", "import time; time.sleep(10**9)"]
