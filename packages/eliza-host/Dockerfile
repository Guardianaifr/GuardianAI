FROM node:22.23.4-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY dist ./dist
EXPOSE 8080
CMD ["node", "dist/server.js"]
