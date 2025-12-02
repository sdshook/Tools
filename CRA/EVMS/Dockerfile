# EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved
# Main EVMS Application Dockerfile

FROM node:18-alpine AS base

# Install system dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    build-base \
    linux-headers \
    curl \
    git

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY requirements.txt ./

# Install Node.js dependencies
RUN npm ci --only=production

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY config/ ./config/

# Create non-root user
RUN addgroup -g 1001 -S evms && \
    adduser -S evms -u 1001

# Change ownership
RUN chown -R evms:evms /app

# Switch to non-root user
USER evms

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Start application
CMD ["node", "src/index.js"]