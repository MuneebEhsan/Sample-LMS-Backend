FROM node:20-alpine

RUN apk add --no-cache python3 make g++ cairo-dev pango-dev libjpeg-turbo-dev

WORKDIR /app

COPY package.json .
RUN npm install --omit=dev

COPY . .
RUN mkdir -p uploads/scorm logs

EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD wget -qO- http://localhost:4000/health || exit 1

CMD ["node", "src/index.js"]
