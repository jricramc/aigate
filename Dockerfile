FROM python:3.13-slim

RUN apt-get update && apt-get install -y jq curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .

# Generate mitmproxy CA cert
RUN mitmdump --set listen_port=0 & sleep 2 && kill $! 2>/dev/null || true

# Install cert into system trust store
RUN cp /root/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-aigate.crt \
    && update-ca-certificates

# Set proxy env vars so everything routes through aigate automatically
ENV HTTPS_PROXY=http://127.0.0.1:8080
ENV HTTP_PROXY=http://127.0.0.1:8080
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV NODE_EXTRA_CA_CERTS=/root/.mitmproxy/mitmproxy-ca-cert.pem

EXPOSE 8080

ENTRYPOINT ["aigate"]
CMD ["start", "--mode", "redact"]
