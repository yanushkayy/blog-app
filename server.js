const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const DB_PATH = path.join(__dirname, 'data.sqlite');

const db = new sqlite3.Database(DB_PATH);

// Helpers to use sqlite with promises
const dbRun = (sql, params = []) =>
    new Promise((resolve, reject) => {
        db.run(sql, params, function onRun(err) {
            if (err) reject(err);
            else resolve(this);
        });
    });

const dbGet = (sql, params = []) =>
    new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });

const dbAll = (sql, params = []) =>
    new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });

// Initial schema
db.serialize(() => {
    db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    )
  `);

    db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      visibility TEXT NOT NULL DEFAULT 'public', -- public | followers | request
      tags TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);

    db.run(`
    CREATE TABLE IF NOT EXISTS follows (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      follower_id INTEGER NOT NULL,
      followee_id INTEGER NOT NULL,
      UNIQUE (follower_id, followee_id),
      FOREIGN KEY (follower_id) REFERENCES users (id),
      FOREIGN KEY (followee_id) REFERENCES users (id)
    )
  `);

    db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (post_id) REFERENCES posts (id),
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
function authRequired(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: 'Missing Authorization header' });
    const [, token] = header.split(' ');
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

async function isFollower(followerId, followeeId) {
    const row = await dbGet(
        `SELECT 1 FROM follows WHERE follower_id = ? AND followee_id = ?`,
        [followerId, followeeId]
    );
    return Boolean(row);
}

function normalizeTags(rawTags) {
    if (!rawTags) return '';
    if (Array.isArray(rawTags)) {
        return rawTags.map((t) => t.trim()).filter(Boolean).join(',');
    }
    return rawTags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean)
        .join(',');
}

// Auth routes
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    try {
        const existing = await dbGet(`SELECT id FROM users WHERE username = ?`, [username]);
        if (existing) return res.status(409).json({ error: 'Username already taken' });
        const hash = await bcrypt.hash(password, 10);
        await dbRun(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, [username, hash]);
        return res.json({ message: 'Registered successfully' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
    try {
        const user = await dbGet(`SELECT id, password_hash FROM users WHERE username = ?`, [username]);
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '7d' });
        return res.json({ token });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

// Follow routes
app.post('/api/follow', authRequired, async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username is required' });
    try {
        const target = await dbGet(`SELECT id FROM users WHERE username = ?`, [username]);
        if (!target) return res.status(404).json({ error: 'User not found' });
        if (target.id === req.user.id) return res.status(400).json({ error: 'Cannot follow yourself' });
        await dbRun(`INSERT OR IGNORE INTO follows (follower_id, followee_id) VALUES (?, ?)`, [
            req.user.id,
            target.id
        ]);
        return res.json({ message: `Now following ${username}` });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

app.get('/api/following', authRequired, async (req, res) => {
    try {
        const rows = await dbAll(
            `SELECT users.username
       FROM follows
       JOIN users ON follows.followee_id = users.id
       WHERE follows.follower_id = ?`,
            [req.user.id]
        );
        return res.json({ following: rows.map((r) => r.username) });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

// Posts
app.post('/api/posts', authRequired, async (req, res) => {
    const { title, content, visibility = 'public', tags } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'Title and content are required' });
    if (!['public', 'followers', 'request'].includes(visibility)) {
        return res.status(400).json({ error: 'Invalid visibility' });
    }
    const tagString = normalizeTags(tags);
    try {
        const result = await dbRun(
            `INSERT INTO posts (user_id, title, content, visibility, tags) VALUES (?, ?, ?, ?, ?)`,
            [req.user.id, title, content, visibility, tagString]
        );
        return res.json({ id: result.lastID, message: 'Post created' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

app.put('/api/posts/:id', authRequired, async (req, res) => {
    const { id } = req.params;
    const { title, content, visibility, tags } = req.body;
    try {
        const post = await dbGet(`SELECT * FROM posts WHERE id = ?`, [id]);
        if (!post) return res.status(404).json({ error: 'Not found' });
        if (post.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });

        const newTitle = title || post.title;
        const newContent = content || post.content;
        const newVisibility = visibility || post.visibility;
        if (!['public', 'followers', 'request'].includes(newVisibility)) {
            return res.status(400).json({ error: 'Invalid visibility' });
        }
        const newTags = tags !== undefined ? normalizeTags(tags) : post.tags;

        await dbRun(
            `UPDATE posts SET title = ?, content = ?, visibility = ?, tags = ? WHERE id = ?`,
            [newTitle, newContent, newVisibility, newTags, id]
        );
        return res.json({ message: 'Post updated' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

app.delete('/api/posts/:id', authRequired, async (req, res) => {
    const { id } = req.params;
    try {
        const post = await dbGet(`SELECT * FROM posts WHERE id = ?`, [id]);
        if (!post) return res.status(404).json({ error: 'Not found' });
        if (post.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
        await dbRun(`DELETE FROM posts WHERE id = ?`, [id]);
        await dbRun(`DELETE FROM comments WHERE post_id = ?`, [id]);
        return res.json({ message: 'Post deleted' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

// Visibility guard
async function canViewPost(post, viewerId, requested = false) {
    if (!post) return false;
    if (post.visibility === 'public') return true;
    if (viewerId && post.user_id === viewerId) return true;
    if (post.visibility === 'followers') {
        return viewerId ? isFollower(viewerId, post.user_id) : false;
    }
    if (post.visibility === 'request') {
        // "hidden" post: show only for owner or when an explicit request is present
        return Boolean(requested || (viewerId && post.user_id === viewerId));
    }
    return false;
}

app.get('/api/posts/public', async (_req, res) => {
    try {
        const rows = await dbAll(
            `SELECT posts.*, users.username as author
       FROM posts JOIN users ON posts.user_id = users.id
       WHERE posts.visibility = 'public'
       ORDER BY posts.created_at DESC`
        );
        return res.json(rows);
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

app.get('/api/posts/feed', authRequired, async (req, res) => {
    try {
        const rows = await dbAll(
            `SELECT posts.*, users.username as author
       FROM posts
       JOIN users ON posts.user_id = users.id
       WHERE posts.visibility = 'public'
         OR (posts.visibility = 'followers' AND posts.user_id IN (
           SELECT followee_id FROM follows WHERE follower_id = ?
         ))
       ORDER BY posts.created_at DESC`,
            [req.user.id]
        );
        return res.json(rows);
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

app.get('/api/posts/tag/:tag', authRequired, async (req, res) => {
    const tag = req.params.tag;
    try {
        const rows = await dbAll(
            `SELECT posts.*, users.username as author
       FROM posts
       JOIN users ON posts.user_id = users.id
       WHERE (posts.tags LIKE '%' || ? || '%')
         AND (
            posts.visibility = 'public'
            OR posts.user_id = ?
            OR (posts.visibility = 'followers' AND posts.user_id IN (
              SELECT followee_id FROM follows WHERE follower_id = ?
            ))
         )
       ORDER BY posts.created_at DESC`,
            [tag, req.user.id, req.user.id]
        );
        return res.json(rows);
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

app.get('/api/posts/:id', authRequired, async (req, res) => {
    const { id } = req.params;
    const { request: requested } = req.query;
    try {
        const post = await dbGet(
            `SELECT posts.*, users.username as author FROM posts
       JOIN users ON posts.user_id = users.id
       WHERE posts.id = ?`,
            [id]
        );
        if (!post) return res.status(404).json({ error: 'Not found' });
        const asked = requested === '1';
        if (post.visibility === 'request' && !asked && post.user_id !== req.user.id) {
            return res.status(403).json({
                error: 'Hidden post requires explicit request',
                hint: 'Add ?request=1 to view if you have permission to ask'
            });
        }
        const allowed = await canViewPost(post, req.user.id, asked);
        if (!allowed) return res.status(403).json({ error: 'Access denied' });
        return res.json(post);
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

// Comments
app.post('/api/posts/:id/comments', authRequired, async (req, res) => {
    const { id } = req.params;
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'Comment content required' });
    try {
        const post = await dbGet(`SELECT * FROM posts WHERE id = ?`, [id]);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        const allowed = await canViewPost(post, req.user.id, true);
        if (!allowed) return res.status(403).json({ error: 'Access denied' });
        await dbRun(`INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)`, [
            id,
            req.user.id,
            content
        ]);
        return res.json({ message: 'Comment added' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

app.get('/api/posts/:id/comments', authRequired, async (req, res) => {
    const { id } = req.params;
    try {
        const post = await dbGet(`SELECT * FROM posts WHERE id = ?`, [id]);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        const allowed = await canViewPost(post, req.user.id, true);
        if (!allowed) return res.status(403).json({ error: 'Access denied' });
        const comments = await dbAll(
            `SELECT comments.*, users.username as author
       FROM comments
       JOIN users ON comments.user_id = users.id
       WHERE comments.post_id = ?
       ORDER BY comments.created_at ASC`,
            [id]
        );
        return res.json(comments);
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal error' });
    }
});

// Default route
app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

