# LogOps Zero-Leak AI Incident Analytics Platform
FROM node:20-alpine

LABEL maintainer="Enterprise Security Team"
LABEL description="Zero-Leak log redactor and local LLM incident analytics engine"

WORKDIR /app

# Copy dependency definition
COPY server/package.json ./server/

# Install dependencies
RUN cd server && npm install --omit=dev

# Copy source code and prebuilt frontend
COPY server/ ./server/
COPY dist/ ./dist/

# Create data directory for persistence
RUN mkdir -p /app/server/data

# Default environment configuration
ENV PORT=8888 \
    NODE_ENV=production \
    FILTR_URL=http://filtr:8080 \
    LLM_URL=http://ollama:11434 \
    LLM_MODEL=deepseek-r1:8b

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8888/api/health || exit 1

VOLUME ["/app/server/data"]

CMD ["node", "server/server.js"]
