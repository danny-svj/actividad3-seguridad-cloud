# Imagen ACTUALIZADA y mínima (Alpine, Node 22 LTS) - build multi-etapa
FROM node:22-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:22-alpine
# Aplica parches de seguridad del SO y elimina npm/yarn/corepack (no se usan en runtime)
RUN apk upgrade --no-cache \
 && rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx \
           /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn*
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json auth.js server.js ./
# No ejecutar como root
USER node
EXPOSE 3000
HEALTHCHECK CMD wget -qO- http://localhost:3000/api/public || exit 1
CMD ["node", "server.js"]
