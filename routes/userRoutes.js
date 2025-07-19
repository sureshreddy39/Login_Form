const express = require('express');
const router = express.Router();
const { db, hashPassword, comparePassword, validateUser } = require('../config/database');
const jwt = require('jsonwebtoken');

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const token = req.cookies.jwt;
    if (!token) {
        if (req.xhr) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        return res.redirect('/login');
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) {
            if (req.xhr) {
                return res.status(401).json({ error: 'Unauthorized' });
            }
            return res.redirect('/login');
        }
        req.user = user;
        next();
    });
};

// Middleware to prevent cached pages
const preventCache = (req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
};

// Register new user
router.post('/register', async (req, res) => {
    try {
        const user = req.body;
        const errors = validateUser(user);
        
        if (errors.length > 0) {
            return res.status(400).json({ errors });
        }

        // Check if username exists and is not soft deleted
        db.get('SELECT username, is_deleted FROM users WHERE username = ?', [user.username], (err, usernameRow) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            
            // If username exists and is not deleted, return error
            if (usernameRow && !usernameRow.is_deleted) {
                return res.status(400).json({ error: 'Username already exists' });
            }

            // Check if email exists and is not soft deleted
            db.get('SELECT email, is_deleted FROM users WHERE email = ?', [user.email], async (err, emailRow) => {
                if (err) {
                    return res.status(500).json({ error: 'Database error' });
                }
                
                // If email exists and is not deleted, return error
                if (emailRow && !emailRow.is_deleted) {
                    return res.status(400).json({ error: 'Email already exists' });
                }

                // If username exists but is deleted, update the existing record
                if (usernameRow && usernameRow.is_deleted) {
                    const hashedPassword = await hashPassword(user.password);
                    db.run(`
                        UPDATE users 
                        SET username = ?, email = ?, password = ?, contact = ?, address = ?, 
                            is_deleted = 0, deleted_at = NULL, updated_at = CURRENT_TIMESTAMP 
                        WHERE username = ?
                    `, [user.username, user.email, hashedPassword, user.contact, user.address, user.username], function(err) {
                        if (err) {
                            if (err.message.includes('UNIQUE constraint failed')) {
                                return res.status(400).json({ error: 'Email already exists' });
                            }
                            return res.status(500).json({ error: 'Error updating user' });
                        }
                        res.status(201).json({ message: 'User created successfully' });
                    });
                } 
                // If email exists but is deleted, update the existing record
                else if (emailRow && emailRow.is_deleted) {
                    const hashedPassword = await hashPassword(user.password);
                    db.run(`
                        UPDATE users 
                        SET username = ?, email = ?, password = ?, contact = ?, address = ?, 
                            is_deleted = 0, deleted_at = NULL, updated_at = CURRENT_TIMESTAMP 
                        WHERE email = ?
                    `, [user.username, user.email, hashedPassword, user.contact, user.address, user.email], function(err) {
                        if (err) {
                            if (err.message.includes('UNIQUE constraint failed')) {
                                return res.status(400).json({ error: 'Username already exists' });
                            }
                            return res.status(500).json({ error: 'Error updating user' });
                        }
                        res.status(201).json({ message: 'User created successfully' });
                    });
                } else {
                    // Create new user if neither username nor email exists
                    const hashedPassword = await hashPassword(user.password);
                    db.run(`
                        INSERT INTO users (username, email, password, contact, address)
                        VALUES (?, ?, ?, ?, ?)
                    `, [user.username, user.email, hashedPassword, user.contact, user.address], function(err) {
                        if (err) {
                            if (err.message.includes('UNIQUE constraint failed')) {
                                if (err.message.includes('username')) {
                                    return res.status(400).json({ error: 'Username already exists' });
                                } else {
                                    return res.status(400).json({ error: 'Email already exists' });
                                }
                            }
                            return res.status(500).json({ error: 'Error creating user' });
                        }
                        res.status(201).json({ message: 'User created successfully' });
                    });
                }
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Login user
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        db.get('SELECT * FROM users WHERE email = ? AND is_deleted = 0', [email], async (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (!user) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const validPassword = await comparePassword(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const token = jwt.sign(
                { id: user.id, email: user.email },
                process.env.JWT_SECRET || 'your-secret-key',
                { expiresIn: '24h' }
            );

            res.cookie('jwt', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                maxAge: 24 * 60 * 60 * 1000 // 24 hours
            });

            res.json({ message: 'Login successful' });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Protected routes
router.use(authenticateToken);

// Get all users
router.get('/users', (req, res) => {
    db.all('SELECT id, username, email, contact, address, is_deleted FROM users', [], (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(users);
    });
});

// Get single user (protected route)
router.get('/users/:id', (req, res) => {
    db.get('SELECT id, username, email, contact, address, is_deleted FROM users WHERE id = ? AND is_deleted = 0',
        [req.params.id],
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            res.json(user);
        });
});

// Update user
router.put('/users/:id', (req, res) => {
    const updates = req.body;
    const updateFields = [];
    const values = [];

    // Build dynamic update query
    Object.keys(updates).forEach(key => {
        if (['username', 'email', 'contact', 'address'].includes(key)) {
            updateFields.push(`${key} = ?`);
            values.push(updates[key]);
        }
    });

    if (updateFields.length === 0) {
        return res.status(400).json({ error: 'No valid fields to update' });
    }

    // Add updated_at timestamp
    updateFields.push('updated_at = CURRENT_TIMESTAMP');
    values.push(req.params.id);

    // Check username and email constraints
    const checkConstraints = () => {
        // Check if username is being updated
        if (updates.username) {
            // Validate username format
            if (!/^[a-zA-Z0-9]{3,20}$/.test(updates.username)) {
                return res.status(400).json({ 
                    error: 'Username must be 3-20 characters long and contain only letters and numbers' 
                });
            }

            // Check if username is already in use
            db.get(
                'SELECT id FROM users WHERE username = ? AND id != ? AND is_deleted = 0', 
                [updates.username, req.params.id], 
                (err, row) => {
                    if (err) {
                        return res.status(500).json({ error: 'Database error' });
                    }
                    if (row) {
                        return res.status(400).json({ error: 'Username already exists' });
                    }
                    
                    // If username is unique, check email if it's being updated
                    if (updates.email) {
                        checkEmailConstraint();
                    } else {
                        executeUpdate();
                    }
                }
            );
        } 
        // If username is not being updated but email is
        else if (updates.email) {
            checkEmailConstraint();
        } 
        // If neither username nor email is being updated
        else {
            executeUpdate();
        }
    };

    const checkEmailConstraint = () => {
        db.get(
            'SELECT id FROM users WHERE email = ? AND id != ? AND is_deleted = 0', 
            [updates.email, req.params.id], 
            (err, row) => {
                if (err) {
                    return res.status(500).json({ error: 'Database error' });
                }
                if (row) {
                    return res.status(400).json({ error: 'Email already exists' });
                }
                executeUpdate();
            }
        );
    };

    const executeUpdate = () => {
        const query = `
            UPDATE users 
            SET ${updateFields.join(', ')}
            WHERE id = ? AND is_deleted = 0
        `;

        db.run(query, values, function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    if (err.message.includes('username')) {
                        return res.status(400).json({ error: 'Username already exists' });
                    } else {
                        return res.status(400).json({ error: 'Email already exists' });
                    }
                }
                return res.status(500).json({ error: 'Database error' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            res.json({ message: 'User updated successfully' });
        });
    };

    // Start the constraint checking process
    checkConstraints();
});

// Soft delete user
router.delete('/users/:id', (req, res) => {
    db.run(
        'UPDATE users SET is_deleted = 1, deleted_at = CURRENT_TIMESTAMP WHERE id = ?',
        [req.params.id],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            res.json({ message: 'User deleted successfully' });
        }
    );
});

// Restore user
router.post('/users/:id/restore', (req, res) => {
    db.run(
        'UPDATE users SET is_deleted = 0, deleted_at = NULL WHERE id = ?',
        [req.params.id],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            res.json({ message: 'User restored successfully' });
        }
    );
});

// Logout
router.post('/logout', (req, res) => {
    res.clearCookie('jwt');
    res.json({ message: 'Logged out successfully' });
});

module.exports = router; 