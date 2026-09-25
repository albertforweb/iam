FROM node:22-bookworm-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY public ./public
COPY applications.json ./applications.json
COPY docker-entrypoint.js ./docker-entrypoint.js
RUN mkdir -p /app/config /var/lib/iam && chown -R node:node /app /var/lib/iam

ENV NODE_ENV=production \
    PORT=3000 \
    IAM_UI_DIR=/app/public

EXPOSE 3000

USER node

CMD ["node", "docker-entrypoint.js"]
