FROM node:20-alpine AS build
WORKDIR /app
COPY package.json tsconfig.json ./
COPY src/ ./src/
RUN sed -i 's|"file:../swt3-ai-ts"|"^0.5.9"|' package.json && \
    npm install && \
    npx tsc && \
    npm prune --production

FROM node:20-alpine
RUN adduser -D -u 10001 swt3
WORKDIR /app
COPY --from=build /app/dist/ ./dist/
COPY --from=build /app/node_modules/ ./node_modules/
COPY --from=build /app/package.json ./
USER swt3
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:9090/health || exit 1
ENTRYPOINT ["node", "dist/entrypoint.js"]
