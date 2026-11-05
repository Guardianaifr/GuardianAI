# Hosted ElizaOS agent for Render (built from the repo root by render.yaml).
# dist/ is not committed, so this builds it here; the runtime stage matches packages/eliza-host/Dockerfile.
FROM node:22.23.4-slim AS build
WORKDIR /src
COPY packages/guardian-middleware/src ./packages/guardian-middleware/src
COPY packages/eliza-host/package.json ./packages/eliza-host/
RUN cd packages/eliza-host && npm install --no-audit --no-fund
COPY packages/eliza-host/src ./packages/eliza-host/src
RUN cd packages/eliza-host && npm run build

FROM node:22.23.4-slim
WORKDIR /app
ENV NODE_ENV=production
COPY packages/eliza-host/package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --from=build /src/packages/eliza-host/dist ./dist
EXPOSE 8080
CMD ["node", "dist/server.js"]
