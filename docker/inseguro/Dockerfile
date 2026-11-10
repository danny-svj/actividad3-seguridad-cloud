# Imagen base OBSOLETA (Node 14, fin de soporte abril 2023) - solo para demostrar vulnerabilidades
FROM node:14
WORKDIR /app
COPY . .
EXPOSE 3000
CMD ["node", "-e", "require('http').createServer((q,s)=>s.end('ok')).listen(3000)"]
