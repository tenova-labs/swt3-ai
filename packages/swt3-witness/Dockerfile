FROM node:20-alpine
RUN adduser -D -u 10001 swt3
WORKDIR /app
COPY dist/ ./dist/
COPY node_modules/ ./node_modules/
COPY package.json ./
USER swt3
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:9090/health || exit 1
ENTRYPOINT ["node", "dist/entrypoint.js"]
