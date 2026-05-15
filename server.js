require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { google } = require('googleapis');
const initDatabase = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'focus_super_secret_key_2024';

app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// ─── Middleware de autenticación ──────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No autenticado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Sesión inválida o expirada' });
  }
}

// ─── Google OAuth2 Client ─────────────────────────────────────────────────────
function getOAuthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/api/calendar/callback'
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// INICIO ASÍNCRONO DEL SERVIDOR
// ═══════════════════════════════════════════════════════════════════════════════
async function startServer() {
  // Inicializar la base de datos (sql.js es asíncrono)
  const db = await initDatabase();

  // ══════════════════════════════════════════════════════
  // RUTAS DE AUTENTICACIÓN
  // ══════════════════════════════════════════════════════

  app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Usuario y contraseña requeridos' });

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user || !bcrypt.compareSync(password, user.password_hash))
      return res.status(401).json({ error: 'Credenciales incorrectas' });

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ success: true, user: { id: user.id, username: user.username }, token });
  });

  app.get('/api/auth/me', requireAuth, (req, res) => {
    const user = db.prepare('SELECT id, username, google_access_token FROM users WHERE id = ?').get(req.user.id);
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json({ id: user.id, username: user.username, googleConnected: !!user.google_access_token });
  });

  app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true });
  });

  // ══════════════════════════════════════════════════════
  // RUTAS DE PROYECTOS
  // ══════════════════════════════════════════════════════

  app.get('/api/projects', requireAuth, (req, res) => {
    const projects = db.prepare(
      `SELECT p.*,
        COUNT(DISTINCT pl.id) as plan_count,
        SUM(CASE WHEN pl.status = 'completed' THEN 1 ELSE 0 END) as completed_plans
       FROM projects p
       LEFT JOIN plans pl ON pl.project_id = p.id
       WHERE p.user_id = ?
       GROUP BY p.id
       ORDER BY p.updated_at DESC`
    ).all(req.user.id);
    res.json(projects);
  });

  app.post('/api/projects', requireAuth, (req, res) => {
    const { name, description, color } = req.body;
    if (!name) return res.status(400).json({ error: 'El nombre del proyecto es requerido' });

    const result = db.prepare(
      'INSERT INTO projects (user_id, name, description, color) VALUES (?, ?, ?, ?)'
    ).run(req.user.id, name, description || '', color || '#00ffb4');

    const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json(project);
  });

  app.put('/api/projects/:id', requireAuth, (req, res) => {
    const { name, description, status, color } = req.body;
    const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });

    db.prepare(
      `UPDATE projects SET name = ?, description = ?, status = ?, color = ?, updated_at = datetime('now')
       WHERE id = ? AND user_id = ?`
    ).run(
      name ?? project.name, description ?? project.description,
      status ?? project.status, color ?? project.color,
      req.params.id, req.user.id
    );
    res.json(db.prepare('SELECT * FROM projects WHERE id = ?').get(req.params.id));
  });

  app.delete('/api/projects/:id', requireAuth, (req, res) => {
    const result = db.prepare('DELETE FROM projects WHERE id = ? AND user_id = ?')
      .run(req.params.id, req.user.id);
    if (!result.changes) return res.status(404).json({ error: 'Proyecto no encontrado' });
    res.json({ success: true });
  });

  // ══════════════════════════════════════════════════════
  // RUTAS DE PLANES
  // ══════════════════════════════════════════════════════

  app.get('/api/projects/:id/plans', requireAuth, (req, res) => {
    const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });

    const plans = db.prepare(
      `SELECT pl.*,
        COUNT(t.id) as task_count,
        SUM(CASE WHEN t.completed = 1 THEN 1 ELSE 0 END) as completed_tasks
       FROM plans pl
       LEFT JOIN tasks t ON t.plan_id = pl.id
       WHERE pl.project_id = ?
       GROUP BY pl.id
       ORDER BY pl.created_at DESC`
    ).all(req.params.id);

    const plansWithTasks = plans.map(plan => ({
      ...plan,
      tasks: db.prepare('SELECT * FROM tasks WHERE plan_id = ? ORDER BY order_index').all(plan.id)
    }));
    res.json(plansWithTasks);
  });

  app.post('/api/projects/:id/plans', requireAuth, (req, res) => {
    const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });

    const { title, description, priority, due_date } = req.body;
    if (!title) return res.status(400).json({ error: 'El título del plan es requerido' });

    const result = db.prepare(
      'INSERT INTO plans (project_id, user_id, title, description, priority, due_date) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(req.params.id, req.user.id, title, description || '', priority || 'medium', due_date || null);

    res.status(201).json(db.prepare('SELECT * FROM plans WHERE id = ?').get(result.lastInsertRowid));
  });

  app.put('/api/plans/:id', requireAuth, (req, res) => {
    const plan = db.prepare('SELECT * FROM plans WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.id);
    if (!plan) return res.status(404).json({ error: 'Plan no encontrado' });

    const { title, description, status, priority, due_date } = req.body;
    db.prepare(
      `UPDATE plans SET title = ?, description = ?, status = ?, priority = ?, due_date = ?, updated_at = datetime('now')
       WHERE id = ? AND user_id = ?`
    ).run(
      title ?? plan.title, description ?? plan.description,
      status ?? plan.status, priority ?? plan.priority,
      due_date ?? plan.due_date, req.params.id, req.user.id
    );
    res.json(db.prepare('SELECT * FROM plans WHERE id = ?').get(req.params.id));
  });

  app.delete('/api/plans/:id', requireAuth, (req, res) => {
    const result = db.prepare('DELETE FROM plans WHERE id = ? AND user_id = ?')
      .run(req.params.id, req.user.id);
    if (!result.changes) return res.status(404).json({ error: 'Plan no encontrado' });
    res.json({ success: true });
  });

  // ─── Tareas dentro de planes ──────────────────────────────────────────────

  app.post('/api/plans/:id/tasks', requireAuth, (req, res) => {
    const plan = db.prepare('SELECT * FROM plans WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.id);
    if (!plan) return res.status(404).json({ error: 'Plan no encontrado' });

    const { title } = req.body;
    if (!title) return res.status(400).json({ error: 'El título de la tarea es requerido' });

    const maxRow = db.prepare('SELECT MAX(order_index) as mx FROM tasks WHERE plan_id = ?').get(req.params.id);
    const maxOrder = maxRow?.mx || 0;

    const result = db.prepare(
      'INSERT INTO tasks (plan_id, title, order_index) VALUES (?, ?, ?)'
    ).run(req.params.id, title, maxOrder + 1);

    res.status(201).json(db.prepare('SELECT * FROM tasks WHERE id = ?').get(result.lastInsertRowid));
  });

  app.put('/api/tasks/:id', requireAuth, (req, res) => {
    const task = db.prepare(
      `SELECT t.* FROM tasks t JOIN plans p ON p.id = t.plan_id WHERE t.id = ? AND p.user_id = ?`
    ).get(req.params.id, req.user.id);
    if (!task) return res.status(404).json({ error: 'Tarea no encontrada' });

    const { title, completed } = req.body;
    db.prepare('UPDATE tasks SET title = ?, completed = ? WHERE id = ?')
      .run(
        title ?? task.title,
        completed !== undefined ? (completed ? 1 : 0) : task.completed,
        req.params.id
      );
    res.json(db.prepare('SELECT * FROM tasks WHERE id = ?').get(req.params.id));
  });

  app.delete('/api/tasks/:id', requireAuth, (req, res) => {
    const task = db.prepare(
      `SELECT t.id FROM tasks t JOIN plans p ON p.id = t.plan_id WHERE t.id = ? AND p.user_id = ?`
    ).get(req.params.id, req.user.id);
    if (!task) return res.status(404).json({ error: 'Tarea no encontrada' });

    db.prepare('DELETE FROM tasks WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  });

  // ══════════════════════════════════════════════════════
  // RUTAS DE EQUIPOS
  // ══════════════════════════════════════════════════════

  app.get('/api/teams', requireAuth, (req, res) => {
    const teams = db.prepare('SELECT * FROM teams WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
    const result = teams.map(team => ({
      ...team,
      members: db.prepare('SELECT * FROM team_members WHERE team_id = ?').all(team.id),
      projects: db.prepare(
        `SELECT p.* FROM projects p JOIN team_projects tp ON tp.project_id = p.id WHERE tp.team_id = ?`
      ).all(team.id)
    }));
    res.json(result);
  });

  app.post('/api/teams', requireAuth, (req, res) => {
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: 'El nombre del equipo es requerido' });

    const result = db.prepare(
      'INSERT INTO teams (user_id, name, description) VALUES (?, ?, ?)'
    ).run(req.user.id, name, description || '');

    res.status(201).json(db.prepare('SELECT * FROM teams WHERE id = ?').get(result.lastInsertRowid));
  });

  app.put('/api/teams/:id', requireAuth, (req, res) => {
    const team = db.prepare('SELECT * FROM teams WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.id);
    if (!team) return res.status(404).json({ error: 'Equipo no encontrado' });

    const { name, description } = req.body;
    db.prepare('UPDATE teams SET name = ?, description = ? WHERE id = ?')
      .run(name ?? team.name, description ?? team.description, req.params.id);
    res.json(db.prepare('SELECT * FROM teams WHERE id = ?').get(req.params.id));
  });

  app.delete('/api/teams/:id', requireAuth, (req, res) => {
    const result = db.prepare('DELETE FROM teams WHERE id = ? AND user_id = ?')
      .run(req.params.id, req.user.id);
    if (!result.changes) return res.status(404).json({ error: 'Equipo no encontrado' });
    res.json({ success: true });
  });

  app.post('/api/teams/:id/members', requireAuth, (req, res) => {
    const team = db.prepare('SELECT * FROM teams WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.id);
    if (!team) return res.status(404).json({ error: 'Equipo no encontrado' });

    const { name, role, email } = req.body;
    if (!name) return res.status(400).json({ error: 'El nombre del miembro es requerido' });

    const result = db.prepare(
      'INSERT INTO team_members (team_id, name, role, email) VALUES (?, ?, ?, ?)'
    ).run(req.params.id, name, role || '', email || '');
    res.status(201).json(db.prepare('SELECT * FROM team_members WHERE id = ?').get(result.lastInsertRowid));
  });

  app.delete('/api/teams/:id/members/:memberId', requireAuth, (req, res) => {
    const team = db.prepare('SELECT * FROM teams WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.id);
    if (!team) return res.status(404).json({ error: 'Equipo no encontrado' });
    db.prepare('DELETE FROM team_members WHERE id = ? AND team_id = ?')
      .run(req.params.memberId, req.params.id);
    res.json({ success: true });
  });

  app.post('/api/teams/:id/projects', requireAuth, (req, res) => {
    const team = db.prepare('SELECT * FROM teams WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.id);
    if (!team) return res.status(404).json({ error: 'Equipo no encontrado' });

    const { project_id } = req.body;
    try {
      db.prepare('INSERT OR IGNORE INTO team_projects (team_id, project_id) VALUES (?, ?)')
        .run(req.params.id, project_id);
      res.json({ success: true });
    } catch (e) {
      res.status(400).json({ error: 'No se pudo asignar el proyecto' });
    }
  });

  app.delete('/api/teams/:id/projects/:projectId', requireAuth, (req, res) => {
    const team = db.prepare('SELECT * FROM teams WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.id);
    if (!team) return res.status(404).json({ error: 'Equipo no encontrado' });
    db.prepare('DELETE FROM team_projects WHERE team_id = ? AND project_id = ?')
      .run(req.params.id, req.params.projectId);
    res.json({ success: true });
  });

  // ══════════════════════════════════════════════════════
  // RUTAS DE GOOGLE CALENDAR
  // ══════════════════════════════════════════════════════

  app.get('/api/calendar/auth-url', requireAuth, (req, res) => {
    if (!process.env.GOOGLE_CLIENT_ID) {
      return res.status(400).json({ error: 'Google Calendar no configurado. Agrega las credenciales en el archivo .env' });
    }
    const oauth2Client = getOAuthClient();
    const url = oauth2Client.generateAuthUrl({
      access_type: 'offline', prompt: 'consent',
      scope: ['https://www.googleapis.com/auth/calendar.readonly'],
      state: req.user.id.toString()
    });
    res.json({ url });
  });

  app.get('/api/calendar/callback', async (req, res) => {
    const { code, state } = req.query;
    if (!code) return res.status(400).send('Código de autorización no recibido');
    try {
      const oauth2Client = getOAuthClient();
      const { tokens } = await oauth2Client.getToken(code);
      db.prepare(
        `UPDATE users SET google_access_token = ?, google_refresh_token = ?, google_token_expiry = ? WHERE id = ?`
      ).run(tokens.access_token, tokens.refresh_token, tokens.expiry_date, parseInt(state));
      res.redirect('/#settings?google=connected');
    } catch (error) {
      console.error('Error de Google OAuth:', error);
      res.redirect('/#settings?google=error');
    }
  });

  app.get('/api/calendar/events', requireAuth, async (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!user || !user.google_access_token)
      return res.status(400).json({ error: 'Google Calendar no conectado', connected: false });

    try {
      const oauth2Client = getOAuthClient();
      oauth2Client.setCredentials({
        access_token: user.google_access_token,
        refresh_token: user.google_refresh_token,
        expiry_date: user.google_token_expiry
      });
      oauth2Client.on('tokens', (tokens) => {
        if (tokens.access_token)
          db.prepare('UPDATE users SET google_access_token = ? WHERE id = ?').run(tokens.access_token, req.user.id);
      });

      const calendar = google.calendar({ version: 'v3', auth: oauth2Client });
      const now = new Date();
      const thirtyDaysLater = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

      const response = await calendar.events.list({
        calendarId: 'primary',
        timeMin: now.toISOString(),
        timeMax: thirtyDaysLater.toISOString(),
        maxResults: 50, singleEvents: true, orderBy: 'startTime'
      });
      res.json({ connected: true, events: response.data.items || [] });
    } catch (error) {
      console.error('Error al obtener eventos:', error);
      res.status(500).json({ error: 'Error al obtener eventos del calendario' });
    }
  });

  app.delete('/api/calendar/disconnect', requireAuth, (req, res) => {
    db.prepare(
      'UPDATE users SET google_access_token = NULL, google_refresh_token = NULL, google_token_expiry = NULL WHERE id = ?'
    ).run(req.user.id);
    res.json({ success: true });
  });

  // ══════════════════════════════════════════════════════
  // INICIAR SERVIDOR
  // ══════════════════════════════════════════════════════
  app.listen(PORT, () => {
    console.log(`\n🚀 Focus corriendo en http://localhost:${PORT}`);
    console.log(`   Presiona Ctrl+C para detener el servidor.\n`);
  });
}

// Iniciar y capturar errores de arranque
startServer().catch(err => {
  console.error('❌ Error al iniciar el servidor:', err);
  process.exit(1);
});
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          