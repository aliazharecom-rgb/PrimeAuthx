require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs').promises;

const app = express();

// ============================================================
// CONFIGURATION
// ============================================================

const JWT_SECRET = process.env.JWT_SECRET || 'prime_auth_super_secret_2026';
const BASE_URL = process.env.BASE_URL || 'https://prime-auth-olnfq2weu-aliazharecom-rgbs-projects.vercel.app';
const PORT = process.env.PORT || 3000;
const DB_PATH = './database';

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors({
    origin: [
        BASE_URL,
        'https://prime-auth-olnfq2weu-aliazharecom-rgbs-projects.vercel.app',
        'http://localhost:3000',
        'http://localhost:5000'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

// ============================================================
// DATABASE HELPERS
// ============================================================

async function readJSON(file) {
    try {
        const data = await fs.readFile(file, 'utf8');
        return JSON.parse(data);
    } catch { return []; }
}

async function writeJSON(file, data) {
    await fs.writeFile(file, JSON.stringify(data, null, 2));
}

// ============================================================
// SERVE PAGES
// ============================================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

function authenticate(req, res, next) {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// ============================================================
// GOOGLE OAUTH
// ============================================================

app.get('/auth/google', (req, res) => {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const redirectUri = `${BASE_URL}/api/auth/google/callback`;
    res.redirect(
        `https://accounts.google.com/o/oauth2/v2/auth?` +
        `client_id=${clientId}` +
        `&redirect_uri=${redirectUri}` +
        `&response_type=code` +
        `&scope=email%20profile`
    );
});

app.get('/api/auth/google/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) {
        return res.status(400).send('No code provided');
    }

    try {
        // Exchange code for token
        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                code,
                client_id: process.env.GOOGLE_CLIENT_ID,
                client_secret: process.env.GOOGLE_CLIENT_SECRET,
                redirect_uri: `${BASE_URL}/api/auth/google/callback`,
                grant_type: 'authorization_code'
            })
        });

        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) {
            throw new Error('Failed to get access token');
        }

        // Get user info
        const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });

        const googleUser = await userRes.json();

        // Create user session
        const token = jwt.sign({
            id: googleUser.sub,
            username: googleUser.name,
            email: googleUser.email,
            avatar: googleUser.picture || `https://ui-avatars.com/api/?name=${encodeURIComponent(googleUser.name)}&background=8871ff&color=fff&size=128`,
            role: 'Tester'
        }, JWT_SECRET, { expiresIn: '7d' });

        // Set cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        // Redirect to dashboard
        res.redirect(`/dashboard?token=${token}`);

    } catch (err) {
        console.error('Google callback error:', err);
        res.status(500).send('Authentication failed');
    }
});

// ============================================================
// DISCORD OAUTH
// ============================================================

app.get('/auth/discord', (req, res) => {
    const clientId = process.env.DISCORD_CLIENT_ID;
    const redirectUri = `${BASE_URL}/api/auth/discord/callback`;
    res.redirect(
        `https://discord.com/api/oauth2/authorize?` +
        `client_id=${clientId}` +
        `&redirect_uri=${redirectUri}` +
        `&response_type=code` +
        `&scope=identify%20email`
    );
});

app.get('/api/auth/discord/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) {
        return res.status(400).send('No code provided');
    }

    try {
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                code,
                client_id: process.env.DISCORD_CLIENT_ID,
                client_secret: process.env.DISCORD_CLIENT_SECRET,
                redirect_uri: `${BASE_URL}/api/auth/discord/callback`,
                grant_type: 'authorization_code'
            })
        });

        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) {
            throw new Error('Failed to get access token');
        }

        const userRes = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });

        const discordUser = await userRes.json();

        const avatarUrl = discordUser.avatar ?
            `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png` :
            `https://ui-avatars.com/api/?name=${encodeURIComponent(discordUser.username)}&background=8871ff&color=fff&size=128`;

        const token = jwt.sign({
            id: discordUser.id,
            username: discordUser.username,
            email: discordUser.email || discordUser.username + '@discord.com',
            avatar: avatarUrl,
            role: 'Tester'
        }, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.redirect(`/dashboard?token=${token}`);

    } catch (err) {
        console.error('Discord callback error:', err);
        res.status(500).send('Authentication failed');
    }
});

// ============================================================
// USER API
// ============================================================

app.get('/api/user', authenticate, async (req, res) => {
    try {
        res.json({
            success: true,
            user: {
                id: req.user.id,
                username: req.user.username,
                email: req.user.email,
                avatar: req.user.avatar,
                role: req.user.role || 'Tester'
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true });
});

// ============================================================
// APPS API
// ============================================================

let apps = [];

app.get('/api/apps', authenticate, (req, res) => {
    res.json({ success: true, apps });
});

app.post('/api/apps', authenticate, (req, res) => {
    const { name, description } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Name required' });
    }

    const app = {
        id: uuidv4(),
        name,
        description: description || '',
        version: '1.0',
        ownerId: req.user.id,
        ownerIdKey: 'OWNER-' + uuidv4().substring(0, 6).toUpperCase(),
        appSecret: require('crypto').randomBytes(32).toString('hex'),
        status: 'Active',
        users: 0,
        licenses: 0,
        createdAt: new Date().toISOString()
    };

    apps.push(app);
    res.json({ success: true, app });
});

app.delete('/api/apps/:id', authenticate, (req, res) => {
    apps = apps.filter(a => a.id !== req.params.id);
    res.json({ success: true });
});

app.put('/api/apps/:id', authenticate, (req, res) => {
    const app = apps.find(a => a.id === req.params.id);
    if (!app) {
        return res.status(404).json({ error: 'App not found' });
    }
    const { name, description, version } = req.body;
    if (name) app.name = name;
    if (description !== undefined) app.description = description;
    if (version) app.version = version;
    res.json({ success: true, app });
});

// ============================================================
// LICENSES API
// ============================================================

let licenses = [];

app.get('/api/licenses', authenticate, (req, res) => {
    res.json({ success: true, licenses });
});

app.post('/api/licenses', authenticate, (req, res) => {
    const { mask, expiry } = req.body;
    let key = mask || 'PRIME-XXXX-XXXX-XXXX';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    key = key.replace(/X/g, () => chars.charAt(Math.floor(Math.random() * chars.length)));
    key = key.replace(/\*/g, () => chars.charAt(Math.floor(Math.random() * chars.length)));

    const license = {
        id: uuidv4(),
        key: key,
        generatedBy: req.user.username || 'Admin',
        duration: (expiry || 365) + ' days',
        uses: '0/1',
        user: '—',
        hwid: '—',
        status: 'Ready',
        created: new Date().toISOString()
    };

    licenses.push(license);
    res.json({ success: true, license });
});

app.delete('/api/licenses/:id', authenticate, (req, res) => {
    licenses = licenses.filter(l => l.id !== req.params.id);
    res.json({ success: true });
});

// ============================================================
// USERS API
// ============================================================

let users = [];

app.get('/api/users', authenticate, (req, res) => {
    const filteredUsers = users.filter(u => u.id !== req.user.id);
    res.json({ success: true, users: filteredUsers });
});

app.post('/api/users', authenticate, (req, res) => {
    const { username, email, hwid, role } = req.body;
    if (!username) {
        return res.status(400).json({ error: 'Username required' });
    }

    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'Username already exists' });
    }

    const user = {
        id: uuidv4(),
        username,
        email: email || username + '@email.com',
        hwid: hwid || 'HWID-' + uuidv4().substring(0, 6).toUpperCase(),
        role: role || 'User',
        status: 'Active',
        created: new Date().toISOString()
    };

    users.push(user);
    res.json({ success: true, user });
});

app.delete('/api/users/:id', authenticate, (req, res) => {
    users = users.filter(u => u.id !== req.params.id);
    res.json({ success: true });
});

// ============================================================
// SESSIONS API
// ============================================================

let sessions = [];

app.get('/api/sessions', authenticate, (req, res) => {
    res.json({ success: true, sessions });
});

app.delete('/api/sessions/:id', authenticate, (req, res) => {
    sessions = sessions.filter(s => s.id !== req.params.id);
    res.json({ success: true });
});

// ============================================================
// ACTIVITIES API
// ============================================================

let activities = [];

app.get('/api/activities', authenticate, (req, res) => {
    res.json({ success: true, activities });
});

// ============================================================
// ROTATE SECRET
// ============================================================

app.post('/api/apps/:id/rotate-secret', authenticate, (req, res) => {
    const app = apps.find(a => a.id === req.params.id);
    if (!app) {
        return res.status(404).json({ error: 'App not found' });
    }

    const newSecret = require('crypto').randomBytes(32).toString('hex');
    app.appSecret = newSecret;
    app.updatedAt = new Date().toISOString();

    res.json({ success: true, secret: newSecret });
});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================================
// START SERVER
// ============================================================

if (process.env.VERCEL) {
    // Vercel serverless
    module.exports = app;
} else {
    // Local development
    app.listen(PORT, () => {
        console.log(`🚀 Prime Auth Server running on port ${PORT}`);
        console.log(`🌐 ${BASE_URL}`);
        console.log(`🔑 Google OAuth: ${process.env.GOOGLE_CLIENT_ID ? '✅' : '❌'}`);
        console.log(`🎮 Discord OAuth: ${process.env.DISCORD_CLIENT_ID ? '✅' : '❌'}`);
    });
}