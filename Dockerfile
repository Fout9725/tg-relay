FROM node:20-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js README.md ./
EXPOSE 7860
CMD ["sh", "-c", "PORT=7860 node server.js"]