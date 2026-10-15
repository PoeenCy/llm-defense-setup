FROM golang:1.24.7-bookworm AS transport
WORKDIR /src
COPY flagtrace/transport/go.mod flagtrace/transport/go.sum ./
RUN go mod download
COPY flagtrace/transport/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /flagtrace-transport .

FROM python:3.11-slim
WORKDIR /runtime
COPY flagtrace/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY --from=transport /flagtrace-transport /usr/local/bin/flagtrace-transport
COPY common ./common
COPY flagtrace ./flagtrace
ENV PYTHONPATH=/runtime PYTHONUNBUFFERED=1
EXPOSE 8095
CMD ["python", "-m", "flagtrace.app.main", "run"]
