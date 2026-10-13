# syntax=docker/dockerfile:1
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY svc1_http.py svc2_tcp.py entrypoint.sh ./
RUN chmod +x entrypoint.sh
EXPOSE 9001 9002
ENTRYPOINT ["./entrypoint.sh"]
