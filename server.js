const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const session = require("express-session");
const { google } = require("googleapis");
const multer = require("multer");
const fs = require("fs");
const crypto = require("crypto");

require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");
const db = new Database(path.join(__dirname, "database.db"));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// =========================
// DATABASE
// =========================

db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS youtube_auth (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    refresh_token TEXT NOT NULL,
    channel_id TEXT,
    channel_title TEXT,
    connected_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    youtube_id TEXT UNIQUE NOT NULL,
    thumbnail TEXT,
    category TEXT DEFAULT 'Other',
    uploader_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uploader_id) REFERENCES users(id)
)`).run();

// Persistent sessions so login survives a server restart.
db.prepare(`CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expire INTEGER NOT NULL
)`).run();

class SQLiteSessionStore extends session.Store {
    constructor(database) {
        super();
        this.db = database;
        this.getStmt = database.prepare("SELECT sess FROM sessions WHERE sid = ? AND expire > ?");
        this.setStmt = database.prepare("INSERT INTO sessions (sid, sess, expire) VALUES (?, ?, ?) ON CONFLICT(sid) DO UPDATE SET sess=excluded.sess, expire=excluded.expire");
        this.destroyStmt = database.prepare("DELETE FROM sessions WHERE sid = ?");
        this.touchStmt = database.prepare("UPDATE sessions SET expire = ? WHERE sid = ?");
        this.clearExpiredStmt = database.prepare("DELETE FROM sessions WHERE expire <= ?");
    }
    get(sid, cb) {
        try {
            const row = this.getStmt.get(sid, Date.now());
            cb(null, row ? JSON.parse(row.sess) : null);
        } catch (e) { cb(e); }
    }
    set(sid, sess, cb) {
        try {
            const expire = sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 30 * 86400000;
            this.setStmt.run(sid, JSON.stringify(sess), expire);
            cb?.(null);
        } catch (e) { cb?.(e); }
    }
    destroy(sid, cb) {
        try { this.destroyStmt.run(sid); cb?.(null); } catch (e) { cb?.(e); }
    }
    touch(sid, sess, cb) {
        try {
            const expire = sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 30 * 86400000;
            this.touchStmt.run(expire, sid);
            cb?.(null);
        } catch (e) { cb?.(e); }
    }
    clearExpired() {
        try { this.clearExpiredStmt.run(Date.now()); } catch (e) { console.error("Session cleanup error:", e); }
    }
}

console.log("Database ready.");

// =========================
// UPLOADS
// =========================
const tempDir = path.join(__dirname, "temp");
if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

const upload = multer({
    dest: tempDir,
    limits: { fileSize: 5 * 1024 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith("video/")) return cb(new Error("Only video files are allowed."));
        cb(null, true);
    }
});

// =========================
// MIDDLEWARE
// =========================
app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

app.use(session({
    store: new SQLiteSessionStore(db),
    secret: process.env.SESSION_SECRET || "change-this-session-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: 1000 * 60 * 60 * 24 * 30
    }
}));

app.use(express.static(PUBLIC_DIR));

// =========================
// HELPERS
// =========================
function requireLogin(req, res, next) {
    if (!req.session.userId) return res.status(401).json({ error: "You must be logged in." });
    next();
}

function getYouTubeClient() {
    const auth = db.prepare("SELECT refresh_token FROM youtube_auth WHERE id = 1").get();
    if (!auth) return null;
    const client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        process.env.GOOGLE_REDIRECT_URI
    );
    client.setCredentials({ refresh_token: auth.refresh_token });
    return client;
}

function getYouTubeAPI() {
    const client = getYouTubeClient();
    return client ? google.youtube({ version: "v3", auth: client }) : null;
}

function cleanText(value, max) {
    return String(value ?? "").trim().slice(0, max);
}

// =========================
// HEALTH
// =========================
app.get("/api/health", (req, res) => {
    res.json({ status: "online", service: "D-Videos", database: "connected" });
});

// =========================
// AUTH
// =========================
app.post("/api/auth/signup", async (req, res) => {
    try {
        const username = cleanText(req.body.username, 32);
        const email = cleanText(req.body.email, 254).toLowerCase();
        const password = String(req.body.password || "");

        if (!username || !email || !password) return res.status(400).json({ error: "All fields are required." });
        if (username.length < 3) return res.status(400).json({ error: "Username must be at least 3 characters." });
        if (!/^[A-Za-z0-9_]+$/.test(username)) return res.status(400).json({ error: "Username can only contain letters, numbers and underscores." });
        if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." });
        if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });

        const existing = db.prepare("SELECT id FROM users WHERE username = ? OR email = ?").get(username, email);
        if (existing) return res.status(409).json({ error: "Username or email is already registered." });

        const passwordHash = await bcrypt.hash(password, 12);
        const result = db.prepare("INSERT INTO users (username,email,password_hash) VALUES (?,?,?)").run(username, email, passwordHash);
        req.session.userId = Number(result.lastInsertRowid);

        res.json({ success: true, user: { id: Number(result.lastInsertRowid), username } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong." });
    }
});

app.post("/api/auth/login", async (req, res) => {
    try {
        const email = cleanText(req.body.email, 254).toLowerCase();
        const password = String(req.body.password || "");
        if (!email || !password) return res.status(400).json({ error: "Email and password are required." });

        const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
        if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Invalid email or password." });

        req.session.userId = user.id;
        res.json({ success: true, user: { id: user.id, username: user.username } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong." });
    }
});

app.get("/api/auth/me", (req, res) => {
    if (!req.session.userId) return res.json({ loggedIn: false });
    const user = db.prepare("SELECT id, username, email, created_at FROM users WHERE id = ?").get(req.session.userId);
    if (!user) return res.json({ loggedIn: false });
    res.json({ loggedIn: true, user });
});

app.post("/api/auth/logout", (req, res) => {
    req.session.destroy(error => {
        if (error) return res.status(500).json({ error: "Could not log out." });
        res.clearCookie("connect.sid");
        res.json({ success: true });
    });
});

// =========================
// YOUTUBE OAUTH
// =========================
app.get("/api/youtube/auth", requireLogin, (req, res) => {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_REDIRECT_URI) {
        return res.status(500).send("Google OAuth environment variables are missing.");
    }
    const state = crypto.randomBytes(32).toString("hex");
    req.session.youtubeOAuthState = state;
    const client = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, process.env.GOOGLE_REDIRECT_URI);
    const authUrl = client.generateAuthUrl({
        access_type: "offline",
        prompt: "consent",
        scope: ["https://www.googleapis.com/auth/youtube.upload", "https://www.googleapis.com/auth/youtube.readonly"],
        state
    });
    res.redirect(authUrl);
});

app.get("/api/youtube/callback", requireLogin, async (req, res) => {
    try {
        const { code, state, error } = req.query;
        if (error) return res.status(400).send(`YouTube authorization failed: ${error}`);
        if (!state || state !== req.session.youtubeOAuthState) return res.status(403).send("Invalid OAuth state.");
        delete req.session.youtubeOAuthState;

        const client = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, process.env.GOOGLE_REDIRECT_URI);
        const { tokens } = await client.getToken(code);
        client.setCredentials(tokens);
        if (!tokens.refresh_token) return res.status(400).send("No refresh token received. Disconnect D-Videos from Google and try again.");

        const youtube = google.youtube({ version: "v3", auth: client });
        const result = await youtube.channels.list({ part: "snippet", mine: true });
        const channel = result.data.items?.[0];
        if (!channel) return res.status(400).send("No YouTube channel was found.");

        db.prepare(`INSERT INTO youtube_auth (id,refresh_token,channel_id,channel_title) VALUES (1,?,?,?)
            ON CONFLICT(id) DO UPDATE SET refresh_token=excluded.refresh_token,channel_id=excluded.channel_id,channel_title=excluded.channel_title,connected_at=CURRENT_TIMESTAMP`)
            .run(tokens.refresh_token, channel.id, channel.snippet?.title || "D-Videos Videos");

        res.redirect("/upload.html?youtube=connected");
    } catch (error) {
        console.error("YouTube OAuth error:", error);
        res.status(500).send(`YouTube connection failed: ${error.message}`);
    }
});

app.get("/api/youtube/status", requireLogin, (req, res) => {
    const channel = db.prepare("SELECT channel_id,channel_title,connected_at FROM youtube_auth WHERE id = 1").get();
    if (!channel) return res.json({ connected: false });
    res.json({ connected: true, channel: { id: channel.channel_id, title: channel.channel_title }, connectedAt: channel.connected_at });
});

// =========================
// VIDEOS
// =========================
app.post("/api/videos/upload", requireLogin, upload.single("video"), async (req, res) => {
    const file = req.file;
    try {
        if (!file) return res.status(400).json({ error: "No video file was uploaded." });
        const title = cleanText(req.body.title, 100);
        const description = cleanText(req.body.description, 5000);
        const allowedCategories = ["Gaming", "Technology", "Music", "Entertainment", "Education", "Other"];
        const category = allowedCategories.includes(req.body.category) ? req.body.category : "Other";
        if (!title) return res.status(400).json({ error: "A title is required." });

        const youtube = getYouTubeAPI();
        if (!youtube) return res.status(400).json({ error: "D-Videos' YouTube channel has not been connected." });

        const result = await youtube.videos.insert({
            part: "snippet,status",
            requestBody: {
                snippet: { title, description: description || "Uploaded to D-Videos.", categoryId: "22" },
                status: { privacyStatus: "public", selfDeclaredMadeForKids: false }
            },
            media: { body: fs.createReadStream(file.path) }
        });

        const youtubeId = result.data.id;
        if (!youtubeId) throw new Error("YouTube did not return a video ID.");
        const thumbnail = `https://img.youtube.com/vi/${youtubeId}/hqdefault.jpg`;

        const saved = db.prepare(`INSERT INTO videos (title,description,youtube_id,thumbnail,category,uploader_id) VALUES (?,?,?,?,?,?)`)
            .run(title, description, youtubeId, thumbnail, category, req.session.userId);

        res.json({ success: true, id: Number(saved.lastInsertRowid), youtubeId, title, thumbnail });
    } catch (error) {
        console.error("Video upload error:", error);
        res.status(500).json({ error: error.message || "Video upload failed." });
    } finally {
        if (file?.path) { try { fs.unlinkSync(file.path); } catch {} }
    }
});

app.get("/api/videos", (req, res) => {
    const videos = db.prepare(`SELECT videos.id,videos.title,videos.description,videos.youtube_id,videos.thumbnail,videos.category,videos.created_at,users.username AS uploader FROM videos JOIN users ON users.id=videos.uploader_id ORDER BY videos.created_at DESC`).all();
    res.json({ videos });
});

app.get("/api/videos/:id", (req, res) => {
    const video = db.prepare(`SELECT videos.id,videos.title,videos.description,videos.youtube_id,videos.thumbnail,videos.category,videos.created_at,users.username AS uploader FROM videos JOIN users ON users.id=videos.uploader_id WHERE videos.id=?`).get(req.params.id);
    if (!video) return res.status(404).json({ error: "Video not found." });
    res.json({ video });
});

// =========================
// ERROR HANDLING
// =========================
app.use((error, req, res, next) => {
    console.error(error);
    if (error instanceof multer.MulterError) return res.status(400).json({ error: error.message });
    res.status(500).json({ error: error.message || "Something went wrong." });
});

setInterval(() => db.prepare("DELETE FROM sessions WHERE expire <= ?").run(Date.now()), 60 * 60 * 1000).unref();

app.listen(PORT, "0.0.0.0", () => console.log(`D-Videos running on port ${PORT}`));
