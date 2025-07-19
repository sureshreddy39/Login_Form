const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const fs = require('fs');

// Ensure data directory exists
const dataDir = path.join(__dirname, '../data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// Create database connection with proper flags
const db = new sqlite3.Database(
    path.join(dataDir, 'users.db'),
    sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
    (err) => {
        if (err) {
            console.error('Error connecting to database:', err);
            process.exit(1); // Exit if we can't connect to database
        } else {
            console.log('Connected to SQLite database');
            initializeDatabase();
        }
    }
);

// Initialize database tables
function initializeDatabase() {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        contact TEXT,
        address TEXT,
        is_deleted INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        deleted_at DATETIME
    )`, (err) => {
        if (err) {
            console.error('Error creating users table:', err);
            process.exit(1); // Exit if we can't create the table
        } else {
            console.log('Users table initialized');
        }
    });
}

// Helper function to hash password
async function hashPassword(password) {
    return await bcrypt.hash(password, 10);
}

// Helper function to compare password
async function comparePassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

// User validation function
function validateUser(user) {
    const errors = [];
    
    // Username validation - only allow letters and numbers, length between 3-20 characters
    if (!user.username) {
        errors.push('Username is required');
    } else if (!/^[a-zA-Z0-9]{3,20}$/.test(user.username)) {
        errors.push('Username must be 3-20 characters long and contain only letters and numbers');
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!user.email || !emailRegex.test(user.email)) {
        errors.push('Invalid email format');
    }

    // Password validation
    if (!user.password || user.password.length < 6) {
        errors.push('Password must be at least 6 characters long');
    }

    // Contact validation
    if (user.contact && !/^\d{10}$/.test(user.contact)) {
        errors.push('Contact must be exactly 10 digits');
    }

    return errors;
}

// Handle cleanup on application shutdown
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
            process.exit(1);
        } else {
            console.log('Database connection closed');
            process.exit(0);
        }
    });
});

module.exports = {
    db,
    hashPassword,
    comparePassword,
    validateUser
}; 