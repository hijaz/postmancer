FROM node:18-slim

WORKDIR /app

# Copy package files first for better layer caching
COPY package*.json ./
RUN npm install --production

# Copy dist folder with compiled code
COPY dist/ ./dist/

# Expose port if needed
EXPOSE 3000

CMD ["node", "dist/src/index.js"]