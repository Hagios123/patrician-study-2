/**
 * PATRICIAN STUDY — server.js
 * Full-stack Node.js + Express + MySQL backend
 * 
 * This file IS your web server. It:
 *  1. Serves the website (public/index.html)
 *  2. Handles all API requests (login, register, data etc.)
 *  3. Talks to the MySQL database
 *  4. Proxies requests to the Claude AI API (keeping your key secret)
 */

// ── LOAD REQUIRED LIBRARIES ───────────────────────────────────────────────────
require('dotenv').config();                          // reads .env file
const express    = require('express');
const mysql      = require('mysql2/promise');
const cors       = require('cors');
const bcrypt     = require('bcrypt');
const session    = require('express-session');
const path       = require('path');
const crypto     = require('crypto');
const fetch      = (...args) => import('node-fetch').then(({default:f}) => f(...args));

const app  = express();
const PORT = process.env.PORT || 3000;

// ── DATABASE CONNECTION POOL ──────────────────────────────────────────────────
const db = mysql.createPool({
  host:            process.env.DB_HOST,
  port:            parseInt(process.env.DB_PORT) || 3306,
  user:            process.env.DB_USER,
  password:        process.env.DB_PASSWORD,
  database:        process.env.DB_NAME,
  connectionLimit: 10,
  waitForConnections: true,
  ssl: { rejectUnauthorized: false }
});

// Test the database connection on startup
db.getConnection()
  .then(conn => { console.log('✅  MySQL connected successfully'); conn.release(); })
  .catch(err => console.error('❌  MySQL connection failed:', err.message));

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.set("trust proxy", 1);
app.use(express.json({ limit: '10mb' }));            // parse JSON request bodies
app.use(express.static(path.join(__dirname, 'public'))); // serve website files

app.use(session({
  secret:            process.env.SESSION_SECRET || 'patrician_secret_2024',
  resave:            false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    secure:   false,
    httpOnly: true,
    maxAge:   7 * 24 * 60 * 60 * 1000  // 7 days
  }
}));

// ── HELPER FUNCTIONS ──────────────────────────────────────────────────────────
const uid = () => crypto.randomBytes(16).toString('hex');
const now = () => Date.now();

/** Middleware: requires user to be logged in */
function auth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ ok: false, error: 'Not authenticated' });
  }
  next();
}

/** Middleware: requires admin role */
function adminOnly(req, res, next) {
  if (req.session.userRole !== 'admin') {
    return res.status(403).json({ ok: false, error: 'Admin only' });
  }
  next();
}

/** Push a notification to a user */
async function pushNotif(userId, text, icon = '🔔', type = 'info') {
  try {
    await db.execute(
      'INSERT INTO notifications (id,user_id,text,icon,type,is_read,ts) VALUES (?,?,?,?,?,0,?)',
      [uid(), userId, text, icon, type, now()]
    );
  } catch (e) { console.error('Notification error:', e.message); }
}

/** Log an activity */
async function logActivity(userId, userName, role, action, detail = '') {
  try {
    await db.execute(
      'INSERT INTO activity_log (id,user_id,user_name,role,action,detail,ts) VALUES (?,?,?,?,?,?,?)',
      [uid(), userId, userName, role, action, detail, now()]
    );
  } catch (e) { console.error('Log error:', e.message); }
}

// ═════════════════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═════════════════════════════════════════════════════════════════════════════

/** POST /api/login — Log in */
app.post('/api/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password) return res.json({ ok: false, error: 'Fill all fields' });

    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    const user = rows[0];

    if (!user) return res.json({ ok: false, error: 'Invalid credentials' });
    if (role !== 'admin' && user.role !== role) return res.json({ ok: false, error: 'Wrong portal for your role' });
    if (user.status === 'banned')   return res.json({ ok: false, error: 'Account banned' });
    if (user.status === 'pending')  return res.json({ ok: false, error: 'Account pending approval' });

    // Check password — admin can use plain password "1204", others use hashed
    let passwordMatch = false;
    if (user.role === 'admin' && password === user.password) {
      passwordMatch = true;  // admin stored as plain initially
    } else {
      passwordMatch = await bcrypt.compare(password, user.password).catch(() => password === user.password);
    }
    if (!passwordMatch) return res.json({ ok: false, error: 'Invalid credentials' });

    req.session.userId   = user.id;
    req.session.userRole = user.role;

    const { password: _, ...safeUser } = user;
    await logActivity(user.id, user.name, user.role, 'LOGIN', 'Signed in');
    res.json({ ok: true, user: safeUser });
  } catch (e) {
    console.error('Login error:', e.message);
    res.json({ ok: false, error: 'Server error' });
  }
});

/** POST /api/register — Create account */
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, role, year, studyingAs } = req.body;
    if (!name || !email || !password || !role) return res.json({ ok: false, error: 'Fill all fields' });
    if (password.length < 6) return res.json({ ok: false, error: 'Password too short (min 6)' });

    const [existing] = await db.execute('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (existing.length > 0) return res.json({ ok: false, error: 'Email already registered' });

    const hashedPw = await bcrypt.hash(password, 10);
    const newId    = uid();

    await db.execute(
      'INSERT INTO users (id,name,email,password,role,year,studying_as,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
      [newId, name, email.toLowerCase(), hashedPw, role, year || null, studyingAs || null, 'pending', now()]
    );

    await db.execute(
      'INSERT INTO pending_approvals (id,user_id,role,requested_at) VALUES (?,?,?,?)',
      [uid(), newId, role, now()]
    );

    // Notify admin
    const [admin] = await db.execute('SELECT id FROM users WHERE role = "admin" LIMIT 1');
    if (admin[0]) await pushNotif(admin[0].id, `New ${role} registration: ${name}`, '👤', 'info');

    res.json({ ok: true, message: 'Account created! Awaiting approval.' });
  } catch (e) {
    console.error('Register error:', e.message);
    res.json({ ok: false, error: 'Server error' });
  }
});

/** POST /api/logout */
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

/** GET /api/me — Get current user session */
app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ ok: false });
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [req.session.userId]);
    if (!rows[0]) return res.status(401).json({ ok: false });
    const { password: _, ...safeUser } = rows[0];
    res.json({ ok: true, user: safeUser });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
//  USER MANAGEMENT
// ═════════════════════════════════════════════════════════════════════════════

/** GET /api/users — Get all users (auth required) */
app.get('/api/users', auth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT id,name,email,role,year,studying_as,status,profile_pic,created_at FROM users');
    res.json({ ok: true, users: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

/** PUT /api/users/:id — Update user (admin or own profile) */
app.put('/api/users/:id', auth, async (req, res) => {
  const { id } = req.params;
  const isAdmin = req.session.userRole === 'admin';
  const isOwn   = req.session.userId === id;
  if (!isAdmin && !isOwn) return res.json({ ok: false, error: 'Forbidden' });

  try {
    const { name, email, year, studying_as, status, role, profile_pic, password } = req.body;
    const updates = [];
    const vals    = [];

    if (name)        { updates.push('name = ?');        vals.push(name); }
    if (email)       { updates.push('email = ?');       vals.push(email.toLowerCase()); }
    if (year)        { updates.push('year = ?');        vals.push(year); }
    if (studying_as) { updates.push('studying_as = ?'); vals.push(studying_as); }
    if (profile_pic) { updates.push('profile_pic = ?'); vals.push(profile_pic); }
    if (isAdmin && status) { updates.push('status = ?'); vals.push(status); }
    if (isAdmin && role)   { updates.push('role = ?');   vals.push(role); }
    if (password && password.length >= 6) {
      const hashed = await bcrypt.hash(password, 10);
      updates.push('password = ?'); vals.push(hashed);
    }

    if (updates.length === 0) return res.json({ ok: false, error: 'Nothing to update' });
    vals.push(id);
    await db.execute(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, vals);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

/** DELETE /api/users/:id — Delete user (admin only) */
app.delete('/api/users/:id', auth, adminOnly, async (req, res) => {
  try {
    await db.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
    await db.execute('DELETE FROM pending_approvals WHERE user_id = ?', [req.params.id]);
    await logActivity(req.session.userId, 'Admin', 'admin', 'DELETE_USER', req.params.id);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// ═════════════════════════════════════════════════════════════════════════════
//  APPROVALS
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/approvals', auth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM pending_approvals ORDER BY requested_at DESC');
    res.json({ ok: true, approvals: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/approvals/:id/approve', auth, async (req, res) => {
  try {
    const [pa] = await db.execute('SELECT * FROM pending_approvals WHERE id = ?', [req.params.id]);
    if (!pa[0]) return res.json({ ok: false, error: 'Not found' });
    await db.execute('UPDATE users SET status = "approved", approved_by = ? WHERE id = ?', [req.session.userId, pa[0].user_id]);
    await db.execute('DELETE FROM pending_approvals WHERE id = ?', [req.params.id]);
    await pushNotif(pa[0].user_id, 'Your account has been approved! You can now sign in.', '✅', 'success');
    await logActivity(req.session.userId, 'Admin', 'admin', 'APPROVE', pa[0].user_id);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/api/approvals/:id/reject', auth, async (req, res) => {
  try {
    const [pa] = await db.execute('SELECT user_id FROM pending_approvals WHERE id = ?', [req.params.id]);
    if (pa[0]) await db.execute('DELETE FROM users WHERE id = ?', [pa[0].user_id]);
    await db.execute('DELETE FROM pending_approvals WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// ═════════════════════════════════════════════════════════════════════════════
//  CLASSROOMS
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/classrooms', auth, async (req, res) => {
  try {
    const [rooms] = await db.execute('SELECT * FROM classrooms ORDER BY created_at DESC');
    for (const room of rooms) {
      const [members] = await db.execute('SELECT student_id FROM classroom_students WHERE classroom_id = ?', [room.id]);
      room.students = members.map(m => m.student_id);
    }
    res.json({ ok: true, classrooms: rooms });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/classrooms', auth, async (req, res) => {
  try {
    const { name, year, subject, description, students } = req.body;
    if (!name) return res.json({ ok: false, error: 'Name required' });
    const id = uid();
    await db.execute(
      'INSERT INTO classrooms (id,name,teacher_id,year,subject,description,created_at) VALUES (?,?,?,?,?,?,?)',
      [id, name, req.session.userId, year || null, subject || null, description || null, now()]
    );
    if (students && students.length) {
      for (const sid of students) {
        await db.execute('INSERT IGNORE INTO classroom_students (classroom_id,student_id) VALUES (?,?)', [id, sid]);
        await pushNotif(sid, `Enrolled in: ${name}`, '🏫', 'info');
      }
    }
    res.json({ ok: true, id });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/api/classrooms/:id', auth, async (req, res) => {
  try {
    await db.execute('DELETE FROM classrooms WHERE id = ?', [req.params.id]);
    await db.execute('DELETE FROM classroom_students WHERE classroom_id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/classrooms/:id/students', auth, async (req, res) => {
  try {
    const { studentId } = req.body;
    await db.execute('INSERT IGNORE INTO classroom_students (classroom_id,student_id) VALUES (?,?)', [req.params.id, studentId]);
    const [room] = await db.execute('SELECT name FROM classrooms WHERE id = ?', [req.params.id]);
    if (room[0]) await pushNotif(studentId, `Enrolled in: ${room[0].name}`, '🏫', 'info');
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/api/classrooms/:id/students/:studentId', auth, async (req, res) => {
  try {
    await db.execute('DELETE FROM classroom_students WHERE classroom_id = ? AND student_id = ?', [req.params.id, req.params.studentId]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// ═════════════════════════════════════════════════════════════════════════════
//  ASSIGNMENTS + GRADING
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/assignments', auth, async (req, res) => {
  try {
    const [asgns] = await db.execute('SELECT * FROM assignments ORDER BY created_at DESC');
    for (const a of asgns) {
      const [subs] = await db.execute('SELECT * FROM submissions WHERE assignment_id = ?', [a.id]);
      a.submissions = subs;
    }
    res.json({ ok: true, assignments: asgns });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/assignments', auth, async (req, res) => {
  try {
    const { title, description, dueDate, maxScore, assignedYear, assignedGroup, assignedTo } = req.body;
    if (!title) return res.json({ ok: false, error: 'Title required' });
    const id = uid();
    await db.execute(
      'INSERT INTO assignments (id,teacher_id,title,description,due_date,max_score,assigned_year,assigned_group,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
      [id, req.session.userId, title, description || null, dueDate || null, maxScore || 100, assignedYear || null, assignedGroup || null, now()]
    );
    // Notify assigned students
    if (assignedTo && assignedTo.length) {
      for (const sid of assignedTo) await pushNotif(sid, `New assignment: ${title}`, '📋', 'info');
    }
    await logActivity(req.session.userId, 'Teacher', 'teacher', 'ASSIGNMENT', title);
    res.json({ ok: true, id });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/api/assignments/:id', auth, async (req, res) => {
  try {
    await db.execute('DELETE FROM assignments WHERE id = ?', [req.params.id]);
    await db.execute('DELETE FROM submissions WHERE assignment_id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/assignments/:id/submit', auth, async (req, res) => {
  try {
    const { content } = req.body;
    if (!content) return res.json({ ok: false, error: 'Write something' });
    const subId = uid();
    await db.execute(
      'INSERT INTO submissions (id,assignment_id,student_id,content,submitted_at) VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE content=?,submitted_at=?',
      [subId, req.params.id, req.session.userId, content, now(), content, now()]
    );
    const [asgn] = await db.execute('SELECT teacher_id,title FROM assignments WHERE id = ?', [req.params.id]);
    if (asgn[0]) {
      const [uname] = await db.execute('SELECT name FROM users WHERE id = ?', [req.session.userId]);
      await pushNotif(asgn[0].teacher_id, `${uname[0]?.name} submitted: ${asgn[0].title}`, '📤', 'info');
    }
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/assignments/:id/grade/:studentId', auth, async (req, res) => {
  try {
    const { score, feedback, maxScore } = req.body;
    const pct   = Math.round(score / (maxScore || 100) * 100);
    const grade = pct >= 90 ? 'A' : pct >= 80 ? 'B' : pct >= 70 ? 'C' : pct >= 60 ? 'D' : 'F';
    await db.execute(
      'UPDATE submissions SET grade_score=?,grade_letter=?,feedback=?,graded_by=?,graded_at=? WHERE assignment_id=? AND student_id=?',
      [score, grade, feedback || null, req.session.userId, now(), req.params.id, req.params.studentId]
    );
    // Save to grades table for analytics
    const [asgn] = await db.execute('SELECT title FROM assignments WHERE id = ?', [req.params.id]);
    await db.execute(
      'INSERT INTO grades (id,student_id,type,subject,score,grade,ts) VALUES (?,?,?,?,?,?,?)',
      [uid(), req.params.studentId, 'assignment', asgn[0]?.title || 'Assignment', pct, grade, now()]
    );
    await pushNotif(req.params.studentId, `Assignment graded: ${score}/${maxScore} (${grade})`, '📊', 'info');
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// ═════════════════════════════════════════════════════════════════════════════
//  MESSAGES
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/messages/group/:groupId', auth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM messages WHERE group_id = ? AND type = "group" ORDER BY ts ASC', [req.params.groupId]);
    res.json({ ok: true, messages: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.get('/api/messages/dm/:userId', auth, async (req, res) => {
  try {
    const me = req.session.userId, them = req.params.userId;
    const [rows] = await db.execute(
      'SELECT * FROM messages WHERE type="dm" AND ((from_id=? AND to_id=?) OR (from_id=? AND to_id=?)) ORDER BY ts ASC',
      [me, them, them, me]
    );
    res.json({ ok: true, messages: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/messages', auth, async (req, res) => {
  try {
    const { type, groupId, toId, content, contentType } = req.body;
    if (!content) return res.json({ ok: false, error: 'Content required' });
    await db.execute(
      'INSERT INTO messages (id,type,group_id,from_id,to_id,content,content_type,ts) VALUES (?,?,?,?,?,?,?,?)',
      [uid(), type || 'dm', groupId || null, req.session.userId, toId || null, content, contentType || 'text', now()]
    );
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/api/messages/:id', auth, async (req, res) => {
  if (req.session.userRole !== 'teacher' && req.session.userRole !== 'admin') {
    return res.json({ ok: false, error: 'Insufficient permissions' });
  }
  try {
    await db.execute('DELETE FROM messages WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// ═════════════════════════════════════════════════════════════════════════════
//  GROUPS
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/groups', auth, async (req, res) => {
  try {
    const [groups] = await db.execute('SELECT * FROM groups_table ORDER BY created_at DESC');
    for (const g of groups) {
      const [members] = await db.execute('SELECT user_id FROM group_members WHERE group_id = ?', [g.id]);
      g.members = members.map(m => m.user_id);
    }
    res.json({ ok: true, groups });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/groups', auth, async (req, res) => {
  try {
    const { name, year, description, members } = req.body;
    if (!name) return res.json({ ok: false, error: 'Name required' });
    const id = uid();
    await db.execute(
      'INSERT INTO groups_table (id,name,year,description,created_by,created_at) VALUES (?,?,?,?,?,?)',
      [id, name, year || null, description || null, req.session.userId, now()]
    );
    const allMembers = [req.session.userId, ...(members || [])];
    for (const uid2 of allMembers) {
      await db.execute('INSERT IGNORE INTO group_members (group_id,user_id) VALUES (?,?)', [id, uid2]);
    }
    res.json({ ok: true, id });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/groups/:id/members', auth, async (req, res) => {
  try {
    await db.execute('INSERT IGNORE INTO group_members (group_id,user_id) VALUES (?,?)', [req.params.id, req.body.userId]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/api/groups/:id/members/:userId', auth, async (req, res) => {
  try {
    await db.execute('DELETE FROM group_members WHERE group_id=? AND user_id=?', [req.params.id, req.params.userId]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/api/groups/:id', auth, async (req, res) => {
  try {
    await db.execute('DELETE FROM groups_table WHERE id = ?', [req.params.id]);
    await db.execute('DELETE FROM group_members WHERE group_id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// ═════════════════════════════════════════════════════════════════════════════
//  FRIENDS
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/friends', auth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM friends WHERE from_id = ? OR to_id = ?', [req.session.userId, req.session.userId]);
    res.json({ ok: true, friends: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/friends/request', auth, async (req, res) => {
  try {
    const { toId } = req.body;
    await db.execute('INSERT INTO friends (id,from_id,to_id,status) VALUES (?,?,?,"pending")', [uid(), req.session.userId, toId]);
    const [u] = await db.execute('SELECT name FROM users WHERE id = ?', [req.session.userId]);
    await pushNotif(toId, `${u[0]?.name} sent you a friend request`, '👤', 'info');
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.put('/api/friends/:id/accept', auth, async (req, res) => {
  try {
    const [f] = await db.execute('SELECT * FROM friends WHERE id = ?', [req.params.id]);
    await db.execute('UPDATE friends SET status = "accepted" WHERE id = ?', [req.params.id]);
    if (f[0]) {
      const [u] = await db.execute('SELECT name FROM users WHERE id = ?', [req.session.userId]);
      await pushNotif(f[0].from_id, `${u[0]?.name} accepted your friend request`, '✓', 'success');
    }
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/api/friends/:id', auth, async (req, res) => {
  try {
    await db.execute('DELETE FROM friends WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// ═════════════════════════════════════════════════════════════════════════════
//  SCHEDULES, QUIZZES, GRADES, NOTIFICATIONS, ANNOUNCEMENTS, FORUM
// ═════════════════════════════════════════════════════════════════════════════

// Schedules
app.get('/api/schedules', auth, async (req, res) => {
  try {
    const where = req.session.userRole === 'admin' ? '' : 'WHERE user_id = ?';
    const params = req.session.userRole === 'admin' ? [] : [req.session.userId];
    const [rows] = await db.execute(`SELECT * FROM schedules ${where} ORDER BY created_at DESC`, params);
    rows.forEach(r => { try { r.subjects = JSON.parse(r.subjects); r.generated = JSON.parse(r.generated || r['\`generated\`']); } catch {} });
    res.json({ ok: true, schedules: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/schedules', auth, async (req, res) => {
  try {
    const { id, name, subjects, startDate, startTime, breakMin, generated } = req.body;
    const sid        = id || uid();
    const safeName   = name || 'My Schedule';
    const safeSubs   = JSON.stringify(subjects   || []);
    const safeGen    = JSON.stringify(generated  || []);
    const safeDate   = startDate  || '';
    const safeTime   = startTime  || '09:00';
    const safeBreak  = breakMin   || 10;
    const ts         = now();
    await db.execute(
      `INSERT INTO schedules
         (id, user_id, name, subjects, start_date, start_time, break_min, \`generated\`, created_at)
       VALUES (?,?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE
         name=?, subjects=?, \`generated\`=?, start_date=?, start_time=?, break_min=?`,
      [sid, req.session.userId, safeName, safeSubs, safeDate, safeTime, safeBreak, safeGen, ts,
       safeName, safeSubs, safeGen, safeDate, safeTime, safeBreak]
    );
    res.json({ ok: true, id: sid });
  } catch (e) {
    console.error('Schedule save error:', e.message);
    res.json({ ok: false, error: e.message });
  }
});

app.delete('/api/schedules/:id', auth, async (req, res) => {
  try {
    await db.execute('DELETE FROM schedules WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// Quizzes
app.get('/api/quizzes', auth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM quizzes ORDER BY created_at DESC');
    rows.forEach(r => { try { r.questions = JSON.parse(r.questions); r.assigned_to = JSON.parse(r.assigned_to); } catch {} });
    res.json({ ok: true, quizzes: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/quizzes', auth, async (req, res) => {
  try {
    const { subject, topic, difficulty, questions, assignedTo } = req.body;
    const id = uid();
    await db.execute(
      'INSERT INTO quizzes (id,created_by,subject,topic,difficulty,questions,assigned_to,created_at) VALUES (?,?,?,?,?,?,?,?)',
      [id, req.session.userId, subject, topic || null, difficulty, JSON.stringify(questions), JSON.stringify(assignedTo || []), now()]
    );
    for (const uid2 of (assignedTo || [])) await pushNotif(uid2, `New quiz: ${subject}`, '🧩', 'info');
    res.json({ ok: true, id });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// Grades
app.get('/api/grades', auth, async (req, res) => {
  try {
    const where = req.session.userRole === 'admin' ? '' : 'WHERE student_id = ?';
    const params = req.session.userRole === 'admin' ? [] : [req.session.userId];
    const [rows] = await db.execute(`SELECT * FROM grades ${where} ORDER BY ts DESC`, params);
    res.json({ ok: true, grades: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/grades', auth, async (req, res) => {
  try {
    const { studentId, type, subject, topic, score, grade } = req.body;
    await db.execute(
      'INSERT INTO grades (id,student_id,type,subject,topic,score,grade,ts) VALUES (?,?,?,?,?,?,?,?)',
      [uid(), studentId || req.session.userId, type, subject, topic || null, score, grade, now()]
    );
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// Notifications
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM notifications WHERE user_id = ? ORDER BY ts DESC LIMIT 100', [req.session.userId]);
    res.json({ ok: true, notifications: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.put('/api/notifications/read-all', auth, async (req, res) => {
  try {
    await db.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', [req.session.userId]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/api/notifications', auth, async (req, res) => {
  try {
    await db.execute('DELETE FROM notifications WHERE user_id = ?', [req.session.userId]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// Announcements
app.get('/api/announcements', auth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM announcements ORDER BY pinned DESC, created_at DESC');
    res.json({ ok: true, announcements: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/announcements', auth, async (req, res) => {
  try {
    const { title, body, targetRole } = req.body;
    if (!title || !body) return res.json({ ok: false, error: 'Fill all fields' });
    const id = uid();
    await db.execute(
      'INSERT INTO announcements (id,title,body,target_role,author_id,pinned,created_at) VALUES (?,?,?,?,?,0,?)',
      [id, title, body, targetRole || 'all', req.session.userId, now()]
    );
    const where = targetRole === 'all' ? '' : 'AND role = ?';
    const params = targetRole === 'all' ? [] : [targetRole];
    const [users] = await db.execute(`SELECT id FROM users WHERE status = "approved" ${where}`, params);
    for (const u of users) await pushNotif(u.id, `New announcement: ${title}`, '📢', 'info');
    await logActivity(req.session.userId, req.session.userRole, req.session.userRole, 'ANNOUNCEMENT', title);
    res.json({ ok: true, id });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.put('/api/announcements/:id/pin', auth, async (req, res) => {
  try {
    await db.execute('UPDATE announcements SET pinned = NOT pinned WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/api/announcements/:id', auth, async (req, res) => {
  try {
    await db.execute('DELETE FROM announcements WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// Forum
app.get('/api/forum', auth, async (req, res) => {
  try {
    const [posts] = await db.execute('SELECT * FROM forum_posts ORDER BY pinned DESC, created_at DESC');
    for (const post of posts) {
      const [replies] = await db.execute('SELECT * FROM forum_replies WHERE post_id = ? ORDER BY created_at ASC', [post.id]);
      post.replies = replies;
    }
    res.json({ ok: true, posts });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/forum', auth, async (req, res) => {
  try {
    const { title, category, body } = req.body;
    if (!title || !body) return res.json({ ok: false, error: 'Fill all fields' });
    const id = uid();
    await db.execute(
      'INSERT INTO forum_posts (id,title,category,body,author_id,votes,pinned,created_at) VALUES (?,?,?,?,?,0,0,?)',
      [id, title, category || 'General', body, req.session.userId, now()]
    );
    res.json({ ok: true, id });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/forum/:id/replies', auth, async (req, res) => {
  try {
    const { body } = req.body;
    if (!body) return res.json({ ok: false, error: 'Write something' });
    await db.execute(
      'INSERT INTO forum_replies (id,post_id,author_id,body,created_at) VALUES (?,?,?,?,?)',
      [uid(), req.params.id, req.session.userId, body, now()]
    );
    const [post] = await db.execute('SELECT author_id,title FROM forum_posts WHERE id = ?', [req.params.id]);
    if (post[0]) {
      const [u] = await db.execute('SELECT name FROM users WHERE id = ?', [req.session.userId]);
      await pushNotif(post[0].author_id, `${u[0]?.name} replied to: ${post[0].title}`, '💬', 'info');
    }
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.put('/api/forum/:id/pin', auth, async (req, res) => {
  try {
    await db.execute('UPDATE forum_posts SET pinned = NOT pinned WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/api/forum/:id', auth, async (req, res) => {
  try {
    await db.execute('DELETE FROM forum_posts WHERE id = ?', [req.params.id]);
    await db.execute('DELETE FROM forum_replies WHERE post_id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/api/forum/:postId/replies/:replyId', auth, async (req, res) => {
  try {
    await db.execute('DELETE FROM forum_replies WHERE id = ?', [req.params.replyId]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// Resources
app.get('/api/resources', auth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM resources ORDER BY created_at DESC');
    res.json({ ok: true, resources: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/resources', auth, async (req, res) => {
  try {
    const { title, type, subject, description, url } = req.body;
    if (!title) return res.json({ ok: false, error: 'Title required' });
    await db.execute(
      'INSERT INTO resources (id,title,type,subject,description,url,uploaded_by,created_at) VALUES (?,?,?,?,?,?,?,?)',
      [uid(), title, type || 'Other', subject || null, description || null, url || null, req.session.userId, now()]
    );
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.delete('/api/resources/:id', auth, async (req, res) => {
  try {
    await db.execute('DELETE FROM resources WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// Events
app.get('/api/events', auth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM events WHERE user_id = ? ORDER BY date ASC', [req.session.userId]);
    res.json({ ok: true, events: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/events', auth, async (req, res) => {
  try {
    const { title, date, type } = req.body;
    if (!title || !date) return res.json({ ok: false, error: 'Fill all fields' });
    await db.execute(
      'INSERT INTO events (id,title,date,type,user_id,created_at) VALUES (?,?,?,?,?,?)',
      [uid(), title, date, type || 'event', req.session.userId, now()]
    );
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// Parent links
app.get('/api/parent-links', auth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM parent_links WHERE parent_id = ?', [req.session.userId]);
    res.json({ ok: true, links: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/parent-links', auth, async (req, res) => {
  try {
    const { studentId } = req.body;
    await db.execute(
      'INSERT IGNORE INTO parent_links (id,parent_id,student_id,linked_at) VALUES (?,?,?,?)',
      [uid(), req.session.userId, studentId, now()]
    );
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// Activity log
app.get('/api/activity-log', auth, adminOnly, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM activity_log ORDER BY ts DESC LIMIT 500');
    res.json({ ok: true, log: rows });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// Study options
app.get('/api/study-options', auth, async (req, res) => {
  const options = ['Computer Science','Electrical Engineering','Mechanical Engineering','Business Administration','Medicine','Law','Arts & Humanities','Data Science','Psychology','Architecture'];
  res.json({ ok: true, options });
});

// ═════════════════════════════════════════════════════════════════════════════
//  AI PROXY — Groq (free, no card required)
// ═════════════════════════════════════════════════════════════════════════════

app.post('/api/ai/chat', auth, async (req, res) => {
  try {
    if (!process.env.GROQ_API_KEY) {
      return res.json({ ok: false, error: 'AI not configured — GROQ_API_KEY missing' });
    }
    const { messages, system, max_tokens } = req.body;

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
      },
      body: JSON.stringify({
        model:      'llama-3.3-70b-versatile',
        max_tokens: max_tokens || 2500,
        messages: [
          { role: 'system', content: system || 'You are a helpful educational AI assistant.' },
          ...messages
        ],
      })
    });

    if (!response.ok) {
      const err = await response.text();
      console.error('Groq API error:', err);
      return res.json({ ok: false, error: 'AI request failed' });
    }

    const data = await response.json();
    const text = data.choices?.[0]?.message?.content;
    if (!text) return res.json({ ok: false, error: 'No response from AI' });

    res.json({ ok: true, text });
  } catch (e) {
    console.error('AI proxy error:', e.message);
    res.json({ ok: false, error: e.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
//  SERVE WEBSITE FOR ALL OTHER ROUTES
// ═════════════════════════════════════════════════════════════════════════════

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ═════════════════════════════════════════════════════════════════════════════
//  START SERVER
// ═════════════════════════════════════════════════════════════════════════════

app.listen(PORT, () => {
  console.log(`\n⚜️  Patrician Study server running on port ${PORT}`);
  console.log(`   Local:   http://localhost:${PORT}`);
  console.log(`   Status:  Ready\n`);
});
