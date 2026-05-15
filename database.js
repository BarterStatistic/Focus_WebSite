/**
 * database.js — Focus App
 * Usa sql.js (SQLite en WebAssembly puro, sin compilación nativa)
 * Expone la misma API síncrona que better-sqlite3 para compatibilidad.
 */

const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'focus.db');

// ─── Wrapper de compatibilidad ────────────────────────────────────────────────
class DB {
  constructor(sqlDb, filePath) {
    this._db = sqlDb;
    this._path = filePath;
  }

  // Guarda el estado actual a disco
  _save() {
    const data = this._db.export();
    fs.writeFileSync(this._path, Buffer.from(data));
  }

  pragma(statement) {
    this._db.run(`PRAGMA ${statement}`);
  }

  // Ejecuta múltiples sentencias SQL (para CREATE TABLE, etc.)
  exec(sql) {
    this._db.exec(sql);
    this._save();
    return this;
  }

  // Devuelve un objeto con métodos run/get/all (compatible con better-sqlite3)
  prepare(sql) {
    const self = this;

    function normalizeParams(args) {
      if (args.length === 0) return [];
      if (args.length === 1 && Array.isArray(args[0])) return args[0];
      return Array.from(args);
    }

    return {
      // Ejecutar INSERT / UPDATE / DELETE
      run(...args) {
        const params = normalizeParams(args);
        self._db.run(sql, params.length ? params : undefined);
        self._save();
        const r1 = self._db.exec('SELECT last_insert_rowid()');
        const r2 = self._db.exec('SELECT changes()');
        return {
          lastInsertRowid: r1[0]?.values[0]?.[0] ?? 0,
          changes:         r2[0]?.values[0]?.[0] ?? 0
        };
      },
      // Obtener una sola fila
      get(...args) {
        const params = normalizeParams(args);
        const stmt = self._db.prepare(sql);
        try {
          if (params.length) stmt.bind(params);
          return stmt.step() ? stmt.getAsObject() : undefined;
        } finally {
          stmt.free();
        }
      },
      // Obtener todas las filas
      all(...args) {
        const params = normalizeParams(args);
        const stmt = self._db.prepare(sql);
        const rows = [];
        try {
          if (params.length) stmt.bind(params);
          while (stmt.step()) rows.push(stmt.getAsObject());
        } finally {
          stmt.free();
        }
        return rows;
      }
    };
  }
}

// ─── Inicialización asíncrona ─────────────────────────────────────────────────
async function initDatabase() {
  const SQL = await initSqlJs();

  // Cargar DB existente o crear nueva
  const sqlDb = fs.existsSync(DB_PATH)
    ? new SQL.Database(fs.readFileSync(DB_PATH))
    : new SQL.Database();

  const db = new DB(sqlDb, DB_PATH);

  // Activar foreign keys
  db._db.run('PRAGMA foreign_keys = ON');

  // ─── Crear tablas ─────────────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      google_access_token TEXT,
      google_refresh_token TEXT,
      google_token_expiry INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CRE