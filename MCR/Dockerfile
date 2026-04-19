# MCR Context Plane - Docker Deployment
#
# This Dockerfile creates a container with both NATS server and MCR Python components.
# For production, consider running NATS separately (or using Synadia Cloud) and
# deploying only the MCR orchestrator in this container.
#
# Build:
#   docker build -t mcr-context-plane .
#
# Run (development):
#   docker run -p 4222:4222 -p 8222:8222 -e ANTHROPIC_API_KEY=your-key mcr-context-plane
#
# Run (with persistent storage):
#   docker run -p 4222:4222 -p 8222:8222 \
#     -v mcr_jetstream:/var/lib/nats/jetstream \
#     -e ANTHROPIC_API_KEY=your-key \
#     mcr-context-plane

FROM python:3.12-slim

# Install NATS server
RUN apt-get update && apt-get install -y curl && \
    curl -L https://github.com/nats-io/nats-server/releases/download/v2.10.25/nats-server-v2.10.25-linux-amd64.tar.gz | \
    tar -xz -C /usr/local/bin --strip-components=1 nats-server-v2.10.25-linux-amd64/nats-server && \
    apt-get remove -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /var/lib/nats/jetstream /app/src

# Copy application files
WORKDIR /app
COPY src/requirements.txt src/
RUN pip install --no-cache-dir -r src/requirements.txt

COPY src/*.py src/
COPY src/nats_config.conf /etc/nats/nats.conf

# Environment variables (override at runtime)
ENV MCR_NATS_URL=nats://localhost:4222
ENV MCR_TENANT=default
ENV MCR_DOMAIN=workflows
ENV MCR_RELEVANCE_RATIO=0.35

# Expose NATS ports
EXPOSE 4222 8222

# Start script
COPY <<EOF /app/start.sh
#!/bin/bash
set -e

echo "Starting NATS server with JetStream..."
nats-server -c /etc/nats/nats.conf &
NATS_PID=\$!

# Wait for NATS to be ready
sleep 2

echo "NATS server ready on port 4222"
echo "JetStream storage: /var/lib/nats/jetstream"
echo ""
echo "MCR Context Plane is ready."
echo "To run the POC: cd /app/src && python mcr_poc_runner.py"
echo "To run live test: cd /app/src && python -m pytest ../tests/test_live_integration.py"
echo ""

# Keep container running
wait \$NATS_PID
EOF

RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]
