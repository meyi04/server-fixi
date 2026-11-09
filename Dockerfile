FROM node:22-slim

ENV NODE_ENV=production
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY src ./src

USER node
CMD ["npm", "start"]
