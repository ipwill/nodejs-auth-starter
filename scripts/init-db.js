import Database from 'better-sqlite3';
import fs from 'fs';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const dbPath = process.env.DB_PATH || path.join(__dirname, '..', 'database.db');
const schemaPath = path.join(__dirname, '..', 'schema.sql');

async function initializeDatabase() {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] Initializing database...`);
    
    try {
        if (fs.existsSync(dbPath)) {
            const backupPath = `${dbPath}.backup-${Date.now()}`;
            fs.copyFileSync(dbPath, backupPath);
            console.log(`Created backup at: ${backupPath}`);
        }
        const db = new Database(dbPath);
        db.pragma('foreign_keys = ON');
        const schema = fs.readFileSync(schemaPath, 'utf8');
        db.exec(schema);
        
        const tables = db.prepare(`
            SELECT name, sql 
            FROM sqlite_master 
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
        `).all();
        
        console.log('\nCreated tables:');
        tables.forEach(table => {
            console.log(`- ${table.name}`);
        });
        
        const triggers = db.prepare(`
            SELECT name, sql 
            FROM sqlite_master 
            WHERE type='trigger'
            ORDER BY name
        `).all();
        
        console.log('\nCreated triggers:');
        triggers.forEach(trigger => {
            console.log(`- ${trigger.name}`);
        });
        
        const indexes = db.prepare(`
            SELECT name, tbl_name 
            FROM sqlite_master 
            WHERE type='index' AND name NOT LIKE 'sqlite_%'
            ORDER BY tbl_name, name
        `).all();
        
        console.log('\nCreated indexes:');
        indexes.forEach(index => {
            console.log(`- ${index.name} (on ${index.tbl_name})`);
        });
        
        db.close();
        
        console.log('\nDatabase initialization complete!');
        console.log(`Database location: ${dbPath}`);
        
    } catch (error) {
        console.error('Error initializing database:', error);
        console.error('Stack trace:', error.stack);
        process.exit(1);
    }
}

initializeDatabase().catch(console.error);
