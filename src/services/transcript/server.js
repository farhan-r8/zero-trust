const config = require('../../config');
const { openDatabase } = require('../../db/connection');
const { startTranscriptService } = require('./app');

const db = openDatabase(config.databasePath);
const server = startTranscriptService({ db, config });

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
