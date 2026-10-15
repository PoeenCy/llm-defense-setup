FROM python:3.11-slim

WORKDIR /runtime/detection/service
COPY detection/service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY detection/service/ .
COPY common /runtime/common
ENV PYTHONPATH=/runtime CONFIG=/runtime/detection/service/services.json
EXPOSE 9999

CMD ["python3", "detection_service.py"]
