const fs = require('node:fs');
const path = require('node:path');
const config = require('../config');
const { openDatabase } = require('./connection');
const { seedDatabase } = require('./seed');

function initializeDatabase(databasePath = config.databasePath) {
  const db = openDatabase(databasePath);
  try {
    db.exec(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
    seedDatabase(db);
  } finally {
    db.close();
  }
}

if (require.main === module) {
  initializeDatabase();
  console.log(`Database dan seed siap: ${config.databasePath}`);
}

module.exports = { initializeDatabase };
