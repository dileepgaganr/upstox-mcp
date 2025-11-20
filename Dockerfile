FROM node:20-alpine

WORKDIR /app

COPY package*.json tsconfig.json ./

RUN npm ci

COPY src/ ./src/

RUN npm run build

ENV NODE_TLS_REJECT_UNAUTHORIZED=0
ENV NODE_ENV=production
ENV NODE_OPTIONS="--max-old-space-size=2048"

CMD ["node", "dist/server.js"]
