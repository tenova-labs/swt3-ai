FROM node:20-alpine
RUN adduser -D -u 10001 swt3 && \
    apk upgrade --no-cache && \
    rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /opt/yarn* /usr/local/bin/yarn /usr/local/bin/yarnpkg
WORKDIR /app
COPY package.json ./
COPY dist/ ./dist/
COPY node_modules/ ./node_modules/
USER swt3
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:9090/health || exit 1
ENTRYPOINT ["node", "dist/entrypoint.js"]
