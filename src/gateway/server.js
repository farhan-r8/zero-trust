const config = require('../config');
const { openDatabase } = require('../db/connection');
const { createGatewayApp } = require('./app');

if (!config.jwtSecret || Buffer.byteLength(config.jwtSecret, 'utf8') < 32) {
  throw new Error('Atur JWT_SECRET acak minimal 32 byte pada .env sebelum menjalankan Gateway');
}
if (!config.gatewaySecret) throw new Error('Atur GATEWAY_SECRET pada .env sebelum menjalankan Gateway');

const db = openDatabase(config.databasePath);
const server = createGatewayApp({ db, config }).listen(config.ports.gateway, '127.0.0.1', () => {
  console.log(`API Gateway berjalan pada port ${config.ports.gateway}`);
});

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
