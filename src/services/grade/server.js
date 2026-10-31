const config = require('../../config');
const { openDatabase } = require('../../db/connection');
const { startGradeService } = require('./app');

const db = openDatabase(config.databasePath);
const { server, timer } = startGradeService({ db, config });

function shutdown() {
  clearInterval(timer);
  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
