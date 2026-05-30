FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
VOLUME ["/app/data"]
CMD ["node", "server.js"]
