const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const session = require("express-session");
const { google } = require("googleapis");
const multer = require("multer");

require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);

// ============================================================
// DATABASE
// ============================================================

const db = new Database(
    path.join(__dirname, "database.db")
);

db.pragma("journal_mode = WAL");

db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS youtube_auth (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        refresh_token TEXT NOT NULL,
        channel_id TEXT,
        channel_title TEXT,
        connected_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT DEFAULT '',
        youtube_id TEXT UNIQUE NOT NULL,
        thumbnail TEXT,
        category TEXT DEFAULT 'Other',
        uploader_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (uploader_id) REFERENCES users(id)
    )
`).run();

console.log("Database ready.");


// ============================================================
// TEMP UPLOADS
// ============================================================

const tempDirectory = path.join(
    __dirname,
    "temp"
);

if (!fs.existsSync(tempDirectory)) {
    fs.mkdirSync(tempDirectory, {
        recursive: true
    });
}


// ============================================================
// MULTER
// ============================================================

const upload = multer({
    dest: tempDirectory,

    limits: {
        fileSize: 5 * 1024 * 1024 * 1024
    },

    fileFilter: (req, file, callback) => {

        if (!file.mimetype.startsWith("video/")) {
            return callback(
                new Error("Only video files are allowed.")
            );
        }

        callback(null, true);
    }
});


// ============================================================
// MIDDLEWARE
// ============================================================

app.use(express.json());
app.use(express.urlencoded({
    extended: true
}));

app.use(
    session({
        secret:
            process.env.SESSION_SECRET ||
            "development-secret",

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,

            sameSite: "lax",

            secure:
                process.env.NODE_ENV === "production",

            maxAge:
                1000 * 60 * 60 * 24 * 30
        }
    })
);


// ============================================================
// FRONTEND
// ============================================================

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);


// ============================================================
// HELPERS
// ============================================================

function requireLogin(req, res, next) {

    if (!req.session.userId) {
        return res.status(401).json({
            error: "You must be logged in."
        });
    }

    next();
}


function getYouTubeClient() {

    const auth = db.prepare(`
        SELECT refresh_token
        FROM youtube_auth
        WHERE id = 1
    `).get();

    if (!auth) {
        return null;
    }

    const client =
        new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET,
            process.env.GOOGLE_REDIRECT_URI
        );

    client.setCredentials({
        refresh_token: auth.refresh_token
    });

    return client;
}


function getYouTubeAPI() {

    const client =
        getYouTubeClient();

    if (!client) {
        return null;
    }

    return google.youtube({
        version: "v3",
        auth: client
    });
}


function escapeHtml(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


// ============================================================
// HEALTH
// ============================================================

app.get("/api/health", (req, res) => {

    res.json({
        status: "online",
        service: "D-Videos",
        database: "connected"
    });

});


// ============================================================
// SIGN UP
// ============================================================

app.post(
    "/api/auth/signup",
    async (req, res) => {

        try {

            const {
                username,
                email,
                password
            } = req.body;

            if (!username || !email || !password) {
                return res.status(400).json({
                    error: "All fields are required."
                });
            }

            const cleanUsername =
                username.trim();

            const cleanEmail =
                email.trim().toLowerCase();

            if (cleanUsername.length < 3) {
                return res.status(400).json({
                    error:
                        "Username must be at least 3 characters."
                });
            }

            if (password.length < 8) {
                return res.status(400).json({
                    error:
                        "Password must be at least 8 characters."
                });
            }

            const existingUser =
                db.prepare(`
                    SELECT id
                    FROM users
                    WHERE username = ?
                       OR email = ?
                `).get(
                    cleanUsername,
                    cleanEmail
                );

            if (existingUser) {
                return res.status(409).json({
                    error:
                        "Username or email is already registered."
                });
            }

            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );

            const result =
                db.prepare(`
                    INSERT INTO users (
                        username,
                        email,
                        password_hash
                    )
                    VALUES (?, ?, ?)
                `).run(
                    cleanUsername,
                    cleanEmail,
                    passwordHash
                );

            req.session.userId =
                result.lastInsertRowid;

            res.json({
                success: true,

                user: {
                    id:
                        result.lastInsertRowid,

                    username:
                        cleanUsername
                }
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error:
                    "Something went wrong."
            });

        }

    }
);


// ============================================================
// LOGIN
// ============================================================

app.post(
    "/api/auth/login",
    async (req, res) => {

        try {

            const {
                email,
                password
            } = req.body;

            if (!email || !password) {
                return res.status(400).json({
                    error:
                        "Email and password are required."
                });
            }

            const cleanEmail =
                email.trim().toLowerCase();

            const user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE email = ?
                `).get(cleanEmail);

            if (!user) {
                return res.status(401).json({
                    error:
                        "Invalid email or password."
                });
            }

            const passwordValid =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );

            if (!passwordValid) {
                return res.status(401).json({
                    error:
                        "Invalid email or password."
                });
            }

            req.session.userId =
                user.id;

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
                error:
                    "Something went wrong."
            });

        }

    }
);


// ============================================================
// CURRENT USER
// ============================================================

app.get(
    "/api/auth/me",
    (req, res) => {

        if (!req.session.userId) {
            return res.json({
                loggedIn: false
            });
        }

        const user =
            db.prepare(`
                SELECT
                    id,
                    username,
                    email,
                    created_at
                FROM users
                WHERE id = ?
            `).get(
                req.session.userId
            );

        if (!user) {
            return res.json({
                loggedIn: false
            });
        }

        res.json({
            loggedIn: true,
            user
        });

    }
);


// ============================================================
// LOGOUT
// ============================================================

app.post(
    "/api/auth/logout",
    (req, res) => {

        req.session.destroy(
            (error) => {

                if (error) {
                    return res.status(500).json({
                        error:
                            "Could not log out."
                    });
                }

                res.json({
                    success: true
                });

            }
        );

    }
);


// ============================================================
// YOUTUBE OAUTH
// ============================================================

app.get(
    "/api/youtube/auth",
    requireLogin,
    (req, res) => {

        if (
            !process.env.GOOGLE_CLIENT_ID ||
            !process.env.GOOGLE_CLIENT_SECRET ||
            !process.env.GOOGLE_REDIRECT_URI
        ) {
            return res.status(500).send(
                "Google OAuth environment variables are missing."
            );
        }

        const state =
            crypto.randomBytes(32).toString("hex");

        req.session.youtubeOAuthState =
            state;

        const oauthClient =
            new google.auth.OAuth2(
                process.env.GOOGLE_CLIENT_ID,
                process.env.GOOGLE_CLIENT_SECRET,
                process.env.GOOGLE_REDIRECT_URI
            );

        const authUrl =
            oauthClient.generateAuthUrl({

                access_type: "offline",

                prompt: "consent",

                scope: [
                    "https://www.googleapis.com/auth/youtube.upload"
                ],

                state

            });

        res.redirect(authUrl);

    }
);


// ============================================================
// YOUTUBE CALLBACK
// ============================================================

app.get(
    "/api/youtube/callback",
    requireLogin,
    async (req, res) => {

        try {

            const {
                code,
                state,
                error
            } = req.query;

            if (error) {
                return res.status(400).send(`
                    <h1>YouTube authorization failed</h1>
                    <p>${escapeHtml(error)}</p>
                `);
            }

            if (
                !state ||
                state !==
                    req.session.youtubeOAuthState
            ) {
                return res.status(403).send(
                    "Invalid OAuth state."
                );
            }

            delete req.session.youtubeOAuthState;

            const oauthClient =
                new google.auth.OAuth2(
                    process.env.GOOGLE_CLIENT_ID,
                    process.env.GOOGLE_CLIENT_SECRET,
                    process.env.GOOGLE_REDIRECT_URI
                );

            const {
                tokens
            } =
                await oauthClient.getToken(code);

            oauthClient.setCredentials(tokens);

            if (!tokens.refresh_token) {
                return res.status(400).send(`
                    <h1>No refresh token received</h1>
                    <p>
                        Revoke D-Videos from your Google account
                        and connect it again.
                    </p>
                `);
            }

            const youtubeAPI =
                google.youtube({
                    version: "v3",
                    auth: oauthClient
                });

            const channelResponse =
                await youtubeAPI.channels.list({
                    part: "snippet",
                    mine: true
                });

            const channel =
                channelResponse.data.items?.[0];

            if (!channel) {
                return res.status(400).send(`
                    <h1>No YouTube channel found</h1>
                    <p>
                        This Google account needs a YouTube channel.
                    </p>
                `);
            }

            db.prepare(`
                INSERT INTO youtube_auth (
                    id,
                    refresh_token,
                    channel_id,
                    channel_title
                )
                VALUES (1, ?, ?, ?)

                ON CONFLICT(id)
                DO UPDATE SET
                    refresh_token =
                        excluded.refresh_token,
                    channel_id =
                        excluded.channel_id,
                    channel_title =
                        excluded.channel_title,
                    connected_at =
                        CURRENT_TIMESTAMP
            `).run(
                tokens.refresh_token,
                channel.id,
                channel.snippet?.title ||
                    "D-Videos Videos"
            );

            console.log(
                "YouTube connected:",
                channel.snippet?.title
            );

            res.redirect(
                "/upload.html?youtube=connected"
            );

        } catch (error) {

            console.error(
                "YouTube OAuth error:",
                error
            );

            res.status(500).send(`
                <h1>YouTube connection failed</h1>
                <p>
                    ${escapeHtml(error.message)}
                </p>
            `);

        }

    }
);


// ============================================================
// YOUTUBE STATUS
// ============================================================

app.get(
    "/api/youtube/status",
    requireLogin,
    (req, res) => {

        const auth =
            db.prepare(`
                SELECT
                    channel_id,
                    channel_title,
                    connected_at
                FROM youtube_auth
                WHERE id = 1
            `).get();

        if (!auth) {
            return res.json({
                connected: false
            });
        }

        res.json({
            connected: true,

            channel: {
                id:
                    auth.channel_id,

                title:
                    auth.channel_title
            },

            connectedAt:
                auth.connected_at
        });

    }
);


// ============================================================
// VIDEO UPLOAD
// ============================================================

app.post(
    "/api/videos/upload",
    requireLogin,
    upload.single("video"),
    async (req, res) => {

        let uploadedFile = null;

        try {

            uploadedFile =
                req.file;

            if (!uploadedFile) {
                return res.status(400).json({
                    error:
                        "No video file was uploaded."
                });
            }

            const title =
                String(
                    req.body.title || ""
                ).trim();

            const description =
                String(
                    req.body.description || ""
                ).trim();

            const category =
                String(
                    req.body.category ||
                    "Other"
                ).trim();

            if (!title) {
                return res.status(400).json({
                    error:
                        "A title is required."
                });
            }

            const youtubeAPI =
                getYouTubeAPI();

            if (!youtubeAPI) {
                return res.status(400).json({
                    error:
                        "The D-Videos YouTube account has not been connected yet."
                });
            }

            console.log(
                `Uploading "${title}" to YouTube...`
            );

            const response =
                await youtubeAPI.videos.insert({

                    part:
                        "snippet,status",

                    requestBody: {

                        snippet: {

                            title,

                            description:
                                description ||
                                "Uploaded to D-Videos.",

                            categoryId: "22"

                        },

                        status: {

                            privacyStatus:
                                "unlisted",

                            selfDeclaredMadeForKids:
                                false

                        }

                    },

                    media: {

                        body:
                            fs.createReadStream(
                                uploadedFile.path
                            )

                    }

                });

            const youtubeId =
                response.data.id;

            if (!youtubeId) {
                throw new Error(
                    "YouTube did not return a video ID."
                );
            }

            const thumbnail =
                `https://img.youtube.com/vi/${youtubeId}/hqdefault.jpg`;

            const result =
                db.prepare(`
                    INSERT INTO videos (
                        title,
                        description,
                        youtube_id,
                        thumbnail,
                        category,
                        uploader_id
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                `).run(
                    title,
                    description,
                    youtubeId,
                    thumbnail,
                    category,
                    req.session.userId
                );

            res.json({

                success: true,

                id:
                    result.lastInsertRowid,

                youtubeId,

                title,

                thumbnail

            });

        } catch (error) {

            console.error(
                "Video upload failed:",
                error
            );

            res.status(500).json({
                error:
                    error.message ||
                    "Video upload failed."
            });

        } finally {

            if (
                uploadedFile &&
                uploadedFile.path
            ) {

                try {
                    fs.unlinkSync(
                        uploadedFile.path
                    );
                } catch {}
            }

        }

    }
);


// ============================================================
// VIDEO LIST
// ============================================================

app.get(
    "/api/videos",
    (req, res) => {

        const videos =
            db.prepare(`
                SELECT
                    videos.id,
                    videos.title,
                    videos.description,
                    videos.youtube_id,
                    videos.thumbnail,
                    videos.category,
                    videos.created_at,
                    users.username AS uploader
                FROM videos
                JOIN users
                    ON users.id =
                        videos.uploader_id
                ORDER BY
                    videos.created_at DESC
            `).all();

        res.json({
            videos
        });

    }
);


// ============================================================
// SINGLE VIDEO
// ============================================================

app.get(
    "/api/videos/:id",
    (req, res) => {

        const video =
            db.prepare(`
                SELECT
                    videos.id,
                    videos.title,
                    videos.description,
                    videos.youtube_id,
                    videos.thumbnail,
                    videos.category,
                    videos.created_at,
                    users.username AS uploader
                FROM videos
                JOIN users
                    ON users.id =
                        videos.uploader_id
                WHERE videos.id = ?
            `).get(req.params.id);

        if (!video) {
            return res.status(404).json({
                error:
                    "Video not found."
            });
        }

        res.json({
            video
        });

    }
);


// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
    (error, req, res, next) => {

        console.error(error);

        if (
            error instanceof multer.MulterError
        ) {

            if (
                error.code ===
                "LIMIT_FILE_SIZE"
            ) {

                return res.status(400).json({
                    error:
                        "The video is too large."
                });

            }

        }

        res.status(500).json({
            error:
                error.message ||
                "Something went wrong."
        });

    }
);


// ============================================================
// START
// ============================================================

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `D-Videos running on port ${PORT}`
        );

    }
);
