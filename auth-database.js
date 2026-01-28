// auth-database.js - минимальная авторизация
const sqlite3 = require('sqlite3').verbose();

class AuthDatabase {
    constructor() {
        // Используем ту же базу данных
        this.db = new sqlite3.Database('./school.db', (err) => {
            if (err) {
                console.error('Ошибка подключения к БД:', err);
            } else {
                console.log('Подключено к базе данных для авторизации');
                this.initAuthTables();
            }
        });
    }

    initAuthTables() {
        // Таблица пользователей (простая)
        this.db.run(`
            CREATE TABLE IF NOT EXISTS auth_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                role TEXT DEFAULT 'user', -- user, moderator, content_manager
                email_verified INTEGER DEFAULT 0,
                verification_code TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME
            )
        `);

        // Таблица сессий (простая)
        this.db.run(`
            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES auth_users (id)
            )
        `);

        // Таблица для специальных кодов доступа
        this.db.run(`
            CREATE TABLE IF NOT EXISTS access_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL, -- moderator, content_manager
                used INTEGER DEFAULT 0,
                used_by INTEGER,
                used_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME
            )
        `);

        console.log('Таблицы авторизации готовы');
    }

    // Простые методы для работы с пользователями
    async createUser(email, password, name) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT INTO auth_users (email, password, name) VALUES (?, ?, ?)`,
                [email, password, name],
                function(err) {
                    if (err) reject(err);
                    else resolve({ id: this.lastID });
                }
            );
        });
    }

    async findUserByEmail(email) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT * FROM auth_users WHERE email = ?`,
                [email],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    async findUserById(id) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT id, email, name, role, email_verified FROM auth_users WHERE id = ?`,
                [id],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    async updateUserVerification(email, code) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `UPDATE auth_users SET email_verified = 1, verification_code = NULL WHERE email = ? AND verification_code = ?`,
                [email, code],
                function(err) {
                    if (err) reject(err);
                    else resolve({ changes: this.changes });
                }
            );
        });
    }

    async setVerificationCode(email, code) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `UPDATE auth_users SET verification_code = ? WHERE email = ?`,
                [code, email],
                function(err) {
                    if (err) reject(err);
                    else resolve({ changes: this.changes });
                }
            );
        });
    }

    async updateUserRole(userId, role) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `UPDATE auth_users SET role = ? WHERE id = ?`,
                [role, userId],
                function(err) {
                    if (err) reject(err);
                    else resolve({ changes: this.changes });
                }
            );
        });
    }

    // Работа с сессиями
    async createSession(userId, token, expiresAt) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT INTO auth_sessions (user_id, token, expires_at) VALUES (?, ?, ?)`,
                [userId, token, expiresAt],
                function(err) {
                    if (err) reject(err);
                    else resolve({ id: this.lastID });
                }
            );
        });
    }

    async findSession(token) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT s.*, u.email, u.name, u.role, u.email_verified 
                 FROM auth_sessions s
                 JOIN auth_users u ON s.user_id = u.id
                 WHERE s.token = ? AND s.expires_at > datetime('now')`,
                [token],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    async deleteSession(token) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `DELETE FROM auth_sessions WHERE token = ?`,
                [token],
                function(err) {
                    if (err) reject(err);
                    else resolve({ changes: this.changes });
                }
            );
        });
    }

    // Работа с кодами доступа
    async createAccessCode(code, role, expiresInDays = 30) {
        const expiresAt = new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000);
        
        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT INTO access_codes (code, role, expires_at) VALUES (?, ?, ?)`,
                [code, role, expiresAt],
                function(err) {
                    if (err) reject(err);
                    else resolve({ id: this.lastID });
                }
            );
        });
    }

    async findAccessCode(code) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT * FROM access_codes WHERE code = ? AND used = 0 AND expires_at > datetime('now')`,
                [code],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    async useAccessCode(code, userId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `UPDATE access_codes SET used = 1, used_by = ?, used_at = datetime('now') WHERE code = ?`,
                [userId, code],
                function(err) {
                    if (err) reject(err);
                    else resolve({ changes: this.changes });
                }
            );
        });
    }

    // Получить роль пользователя по ID
    async getUserRole(userId) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT role FROM auth_users WHERE id = ?`,
                [userId],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row?.role || 'user');
                }
            );
        });
    }

    // Обновить время последнего входа
    async updateLastLogin(userId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `UPDATE auth_users SET last_login = datetime('now') WHERE id = ?`,
                [userId],
                function(err) {
                    if (err) reject(err);
                    else resolve({ changes: this.changes });
                }
            );
        });
    }
}

module.exports = new AuthDatabase();
