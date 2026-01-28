const sqlite3 = require('sqlite3').verbose();
const path = require('path');

class Database {
    constructor() {
        // Создаем базу данных в памяти или файле
        this.db = new sqlite3.Database('./school.db', (err) => {
            if (err) {
                console.error('Ошибка подключения к базе данных:', err);
            } else {
                console.log('Подключено к базе данных SQLite');
                this.initDatabase();
            }
        });
    }

    initDatabase() {
        // Добавляем в initDatabase():
        async initDatabase() {
            try {
                // Существующие таблицы...
        
                // Таблица пользователей
                await this.pool.query(`
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        username VARCHAR(100) NOT NULL,
                        role VARCHAR(50) DEFAULT 'user', -- user, moderator, content_manager, admin
                        email_verified BOOLEAN DEFAULT FALSE,
                        verification_code VARCHAR(10),
                        verification_expires TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        is_active BOOLEAN DEFAULT TRUE
                    )
                `);

        // Таблица сессий
                await this.pool.query(`
                    CREATE TABLE IF NOT EXISTS sessions (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        token VARCHAR(255) UNIQUE NOT NULL,
                        ip_address VARCHAR(45),
                        user_agent TEXT,
                        expires_at TIMESTAMP NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                `);

        // Таблица пригласительных кодов
                await this.pool.query(`
                    CREATE TABLE IF NOT EXISTS invitation_codes (
                        id SERIAL PRIMARY KEY,
                        code VARCHAR(50) UNIQUE NOT NULL,
                        role VARCHAR(50) NOT NULL, -- moderator, content_manager
                        created_by INTEGER REFERENCES users(id),
                        used_by INTEGER REFERENCES users(id),
                        used_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP,
                        max_uses INTEGER DEFAULT 1,
                        use_count INTEGER DEFAULT 0
                    )
                `);

        // Добавляем поля в таблицу идей для контент-менеджмента
                await this.pool.query(`
                    ALTER TABLE ideas 
                    ADD COLUMN IF NOT EXISTS is_featured BOOLEAN DEFAULT FALSE,
                    ADD COLUMN IF NOT EXISTS reviewed_by INTEGER REFERENCES users(id),
                    ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP,
                    ADD COLUMN IF NOT EXISTS review_notes TEXT
                `);

                console.log('✅ Таблицы авторизации созданы/обновлены');

            } catch (error) {
                console.error('❌ Ошибка инициализации БД:', error);
            }
        }
        this.db.run(`
            CREATE TABLE IF NOT EXISTS ideas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                author TEXT NOT NULL,
                votes INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Таблица для комментариев
        this.db.run(`
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idea_id INTEGER NOT NULL,
                author TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (idea_id) REFERENCES ideas (id)
            )
        `);

        // Таблица для голосов (чтобы один пользователь не голосовал много раз)
        this.db.run(`
            CREATE TABLE IF NOT EXISTS votes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idea_id INTEGER NOT NULL,
                user_ip TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(idea_id, user_ip)
            )
        `);
    }

    // Получить все идеи
    getAllIdeas(callback) {
        this.db.all(`
            SELECT i.*, 
                   COUNT(DISTINCT v.id) as vote_count,
                   COUNT(DISTINCT c.id) as comment_count
            FROM ideas i
            LEFT JOIN votes v ON i.id = v.idea_id
            LEFT JOIN comments c ON i.id = c.idea_id
            GROUP BY i.id
            ORDER BY i.votes DESC, i.created_at DESC
        `, callback);
    }

    // Добавить новую идею
    addIdea(title, description, author, callback) {
        this.db.run(
            'INSERT INTO ideas (title, description, author) VALUES (?, ?, ?)',
            [title, description, author],
            callback
        );
    }

    // Проголосовать за идею
    voteForIdea(ideaId, userIp, callback) {
        // Сначала проверяем, не голосовал ли уже пользователь
        this.db.get(
            'SELECT id FROM votes WHERE idea_id = ? AND user_ip = ?',
            [ideaId, userIp],
            (err, row) => {
                if (err) {
                    callback(err);
                } else if (row) {
                    callback(new Error('Вы уже голосовали за эту идею'));
                } else {
                    // Добавляем голос
                    this.db.run(
                        'INSERT INTO votes (idea_id, user_ip) VALUES (?, ?)',
                        [ideaId, userIp],
                        (err) => {
                            if (err) {
                                callback(err);
                            } else {
                                // Обновляем счетчик голосов
                                this.db.run(
                                    'UPDATE ideas SET votes = votes + 1 WHERE id = ?',
                                    [ideaId],
                                    callback
                                );
                            }
                        }
                    );
                }
            }
        );
    }

    // Добавить комментарий
    addComment(ideaId, author, text, callback) {
        this.db.run(
            'INSERT INTO comments (idea_id, author, text) VALUES (?, ?, ?)',
            [ideaId, author, text],
            callback
        );
    }

    // Получить комментарии для идеи
    getComments(ideaId, callback) {
        this.db.all(
            'SELECT * FROM comments WHERE idea_id = ? ORDER BY created_at ASC',
            [ideaId],
            callback
        );
    }
}

module.exports = new Database();

