FROM python:3.11-slim
WORKDIR /runtime/dashboard
COPY dashboard/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY dashboard/app ./app
COPY dashboard/static ./static
COPY common /runtime/common
ENV PYTHONPATH=/runtime
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
