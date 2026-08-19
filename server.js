const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const session = require("express-session");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// =========================
// DATABASE
// =========================

const db = new Database("database.db");

db.pragma("journal_mode = WAL");

// Users table
db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`).run();

console.log("Database ready.");


// =========================
// MIDDLEWARE
// =========================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
    session({
        secret: process.env.SESSION_SECRET || "development-secret",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: false,
            maxAge: 1000 * 60 * 60 * 24 * 30
        }
    })
);


// =========================
// FRONTEND
// =========================

app.use(express.static(path.join(__dirname, "public")));


// =========================
// API
// =========================

app.get("/api/health", (req, res) => {
    res.json({
        status: "online",
        service: "D-Videos",
        database: "connected"
    });
});


// =========================
// SIGN UP
// =========================

app.post("/api/auth/signup", async (req, res) => {

    try {

        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({
                error: "All fields are required."
            });
        }

        if (username.length < 3) {
            return res.status(400).json({
                error: "Username must be at least 3 characters."
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                error: "Password must be at least 8 characters."
            });
        }

        const existingUser = db.prepare(`
            SELECT id
            FROM users
            WHERE username = ? OR email = ?
        `).get(username, email);

        if (existingUser) {
            return res.status(409).json({
                error: "Username or email is already registered."
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const result = db.prepare(`
            INSERT INTO users (
                username,
                email,
                password_hash
            )
            VALUES (?, ?, ?)
        `).run(
            username,
            email,
            passwordHash
        );

        req.session.userId = result.lastInsertRowid;

        res.json({
            success: true,
            user: {
                id: result.lastInsertRowid,
                username
            }
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Something went wrong."
        });

    }

});


// =========================
// LOGIN
// =========================

app.post("/api/auth/login", async (req, res) => {

    try {

        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                error: "Email and password are required."
            });
        }

        const user = db.prepare(`
            SELECT *
            FROM users
            WHERE email = ?
        `).get(email);

        if (!user) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        const passwordValid = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordValid) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        req.session.userId = user.id;

        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username
            }
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Something went wrong."
        });

    }

});


// =========================
// CURRENT USER
// =========================

app.get("/api/auth/me", (req, res) => {

    if (!req.session.userId) {
        return res.json({
            loggedIn: false
        });
    }

    const user = db.prepare(`
        SELECT id, username, email, created_at
        FROM users
        WHERE id = ?
    `).get(req.session.userId);

    if (!user) {
        return res.json({
            loggedIn: false
        });
    }

    res.json({
        loggedIn: true,
        user
    });

});


// =========================
// LOGOUT
// =========================

app.post("/api/auth/logout", (req, res) => {

    req.session.destroy((error) => {

        if (error) {
            return res.status(500).json({
                error: "Could not log out."
            });
        }

        res.json({
            success: true
        });

    });

});


// =========================
// START
// =========================

app.listen(PORT, () => {

    console.log(
        `D-Videos running on http://localhost:${PORT}`
    );

});