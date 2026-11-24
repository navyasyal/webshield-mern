@'
FROM mcr.microsoft.com/playwright:v1.64.1-noble

WORKDIR /app

COPY package*.json ./

RUN npm install --omit=dev

COPY src ./src

ENV NODE_ENV=production
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

CMD ["node", "src/start.js"]
'@ | Set-Content server/Dockerfile