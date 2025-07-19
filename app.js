const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const fs = require('fs');
const userRoutes = require('./routes/userRoutes');

const app = express();

// Ensure data directory exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// Create database connection
const db = new Database(path.join(dataDir, 'users.db'), { 
    fileMustExist: false
});

// Initialize database tables
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        contact TEXT,
        address TEXT,
        is_deleted INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        deleted_at DATETIME
    );
`);

// Drop existing trigger if exists and create new one
db.exec(`DROP TRIGGER IF EXISTS cleanup_deleted_users;`);

// Create the trigger separately
db.exec(`
    CREATE TRIGGER cleanup_deleted_users
    AFTER DELETE ON users
    BEGIN
        SELECT 1;
    END;
`);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Prevent caching for all routes
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
});

// View engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Authentication middleware
const checkAuth = (req, res, next) => {
    const token = req.cookies.jwt;
    if (token) {
        return res.redirect('/dashboard');
    }
    next();
};

// Routes
app.use('/api', userRoutes);

// Page routes
app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', checkAuth, (req, res) => {
    res.render('login');
});

app.get('/register', checkAuth, (req, res) => {
    res.render('register');
});

app.get('/dashboard', (req, res) => {
    const token = req.cookies.jwt;
    if (!token) {
        return res.redirect('/login');
    }
    res.render('dashboard');
});

// Add API routes for permanent delete
app.delete('/api/users/:id/permanent', (req, res) => {
    try {
        const stmt = db.prepare('DELETE FROM users WHERE id = ?');
        const result = stmt.run(req.params.id);
        
        if (result.changes > 0) {
            res.json({ message: 'User permanently deleted' });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        console.error('Error permanently deleting user:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
});

// Handle cleanup on application shutdown
process.on('SIGINT', () => {
    if (db) {
        db.close();
        console.log('Database connection closed');
    }
    process.exit(0);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
