/**
 * Migration script to populate user_history table with existing usernames
 * Date: 2025-03-13 03:37:55
 * Author: cgtwig
 */

import Database from 'better-sqlite3';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dbPath = process.env.DB_PATH || path.join(__dirname, '..', 'database.db');
const db = new Database(dbPath);

function migrateUsernameHistory() {
  console.log('Starting username history migration...');
  console.log(`Current time (UTC): 2025-03-13 03:37:55`);
  console.log(`Migration executed by: cgtwig\n`);
  
  try {
    const tableExists = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='user_history'"
    ).get();
    
    if (!tableExists) {
      console.error('Error: user_history table does not exist. Run init-db.js first.');
      process.exit(1);
    }
    
    console.log('Verifying user_history table structure...');
    const tableInfo = db.prepare("PRAGMA table_info(user_history)").all();
    const hasOldUsername = tableInfo.some(col => col.name === 'old_username');
    
    if (!hasOldUsername) {
      console.error('Error: user_history table is missing the old_username column');
      process.exit(1);
    }
    
    console.log('Creating indices for username history lookup if needed...');
    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_user_history_user_id ON user_history(user_id);
      CREATE INDEX IF NOT EXISTS idx_user_history_old_username ON user_history(old_username);
      CREATE INDEX IF NOT EXISTS idx_user_history_changed_at ON user_history(changed_at);
    `);
    
    const usernameHistoryCount = db.prepare('SELECT COUNT(*) as count FROM user_history WHERE old_username IS NOT NULL').get();
    
    if (usernameHistoryCount.count === 0) {
      console.log('Migrating existing usernames to user_history table...');
      const users = db.prepare('SELECT id, username, email, password FROM users').all();
      const insert = db.prepare(`
        INSERT INTO user_history (user_id, old_username, old_email, old_password, changed_at)
        VALUES (?, ?, ?, ?, ?)
      `);
      const transaction = db.transaction((users) => {
        let migrated = 0;
        for (const user of users) {
          insert.run(user.id, user.username, user.email, user.password, Date.now());
          migrated++;
        }
        return migrated;
      });
      const migratedCount = transaction(users);
      console.log(`Successfully migrated ${migratedCount} usernames to history table.`);
    } else {
      console.log(`Username history already populated with ${usernameHistoryCount.count} entries, skipping migration.`);
    }
    const indices = db.prepare(`
      SELECT name FROM sqlite_master 
      WHERE type='index' AND tbl_name='user_history' 
      AND name LIKE 'idx_user%'
    `).all();
    
    console.log('\nVerified indices:');
    indices.forEach(index => {
      console.log(`- ${index.name}`);
    });
    
    console.log('\nMigration completed successfully.');
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  } finally {
    db.close();
  }
}

migrateUsernameHistory();
