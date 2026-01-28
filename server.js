// server.js - версия для MongoDB
const express = require('express');
const cors = require('cors');
const path = require('path');
const db = require('./database-mongo.js'); // Изменили импорт!

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Статические файлы
app.use(express.static(path.join(__dirname, 'public')));

// Главная страница
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Получить IP пользователя
const getClientIp = (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0] || 
           req.ip || 
           req.connection.remoteAddress;
};

// Проверка здоровья API
app.get('/api/health', async (req, res) => {
    try {
        const connectionStatus = await db.testConnection();
        
        res.json({ 
            status: 'healthy',
            database: connectionStatus.connected ? 'connected' : 'disconnected',
            timestamp: new Date().toISOString(),
            mongo: connectionStatus
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'unhealthy',
            error: error.message 
        });
    }
});

// Добавляем авторизацию
const simpleAuth = require('./simple-auth.js');

// Middleware для проверки авторизации
const authMiddleware = async (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
    
    if (token) {
        const authResult = await simpleAuth.authenticate(token);
        if (authResult.authenticated) {
            req.user = authResult.user;
            req.token = token;
        } else {
            req.user = null;
        }
    } else {
        req.user = null;
    }
    
    next();
};

// Middleware для защиты маршрутов
const requireAuth = (roles = []) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Требуется авторизация' });
        }
        
        if (roles.length > 0 && !roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Недостаточно прав' });
        }
        
        next();
    };
};

// Подключаем middleware ко всем маршрутам
app.use(authMiddleware);

// Получить статистику
app.get('/api/stats', async (req, res) => {
    try {
        const stats = await db.getStats();
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// API Routes

// Получить все идеи
app.get('/api/ideas', async (req, res) => {
    try {
        const ideas = await db.getAllIdeas();
        res.json(ideas);
    } catch (error) {
        console.error('Ошибка загрузки идей:', error);
        res.status(500).json({ error: 'Ошибка загрузки идей. Попробуйте позже.' });
    }
});

// Добавить новую идею
app.post('/api/ideas', async (req, res) => {
    try {
        const { title, description, author } = req.body;
        
        // Валидация
        if (!title || !description) {
            return res.status(400).json({ 
                error: 'Заполните все поля',
                details: 'Нужны название и описание идеи'
            });
        }
        
        if (title.length < 3) {
            return res.status(400).json({ 
                error: 'Название слишком короткое',
                details: 'Минимум 3 символа'
            });
        }
        
        if (description.length < 10) {
            return res.status(400).json({ 
                error: 'Описание слишком короткое',
                details: 'Минимум 10 символов'
            });
        }
        
        const result = await db.addIdea(title, description, author);
        
        res.json({ 
            success: true, 
            message: 'Идея успешно добавлена!',
            id: result.id
        });
        
    } catch (error) {
        console.error('Ошибка добавления идеи:', error);
        
        // Более понятные ошибки для пользователя
        if (error.message.includes('обязательно') || 
            error.message.includes('должно быть')) {
            res.status(400).json({ error: error.message });
        } else {
            res.status(500).json({ error: 'Не удалось добавить идею' });
        }
    }
});

// Проголосовать за идею
app.post('/api/ideas/:id/vote', async (req, res) => {
    try {
        const ideaId = req.params.id;
        const userIp = getClientIp(req);
        
        if (!ideaId) {
            return res.status(400).json({ error: 'Не указан ID идеи' });
        }
        
        await db.voteForIdea(ideaId, userIp);
        
        res.json({ 
            success: true,
            message: 'Ваш голос учтен!'
        });
        
    } catch (error) {
        console.error('Ошибка голосования:', error);
        
        if (error.message.includes('уже голосовали')) {
            res.status(400).json({ error: error.message });
        } else if (error.message.includes('не найдена')) {
            res.status(404).json({ error: 'Идея не найдена' });
        } else {
            res.status(500).json({ error: 'Ошибка голосования' });
        }
    }
});

// Добавить комментарий
app.post('/api/ideas/:id/comments', async (req, res) => {
    try {
        const ideaId = req.params.id;
        const { author, text } = req.body;
        
        if (!text) {
            return res.status(400).json({ 
                error: 'Введите текст комментария'
            });
        }
        
        if (text.length < 2) {
            return res.status(400).json({ 
                error: 'Комментарий слишком короткий'
            });
        }
        
        const result = await db.addComment(ideaId, author, text);
        
        res.json({ 
            success: true,
            message: 'Комментарий добавлен!',
            id: result.id
        });
        
    } catch (error) {
        console.error('Ошибка добавления комментария:', error);
        
        if (error.message.includes('не найдена')) {
            res.status(404).json({ error: 'Идея не найдена' });
        } else {
            res.status(500).json({ error: 'Не удалось добавить комментарий' });
        }
    }
});

// Получить комментарии для идеи
app.get('/api/ideas/:id/comments', async (req, res) => {
    try {
        const ideaId = req.params.id;
        const comments = await db.getComments(ideaId);
        
        res.json(comments);
        
    } catch (error) {
        console.error('Ошибка загрузки комментариев:', error);
        res.status(500).json({ error: 'Не удалось загрузить комментарии' });
    }
});

// Очистить базу данных (ТОЛЬКО ДЛЯ ТЕСТИРОВАНИЯ!)
app.delete('/api/admin/clear', async (req, res) => {
    // Защита: только в режиме разработки
    if (process.env.NODE_ENV !== 'development') {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }
    
    try {
        const result = await db.clearDatabase();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Обработка 404
app.use((req, res) => {
    res.status(404).json({ error: 'Страница не найдена' });
});

// ========== API для авторизации ==========

// Регистрация
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        
        if (!email || !password || !name) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }
        
        const result = await simpleAuth.register(email, password, name);
        res.json(result);
        
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        res.status(400).json({ error: error.message });
    }
});

// Подтверждение email
app.post('/api/auth/verify', async (req, res) => {
    try {
        const { email, code } = req.body;
        
        if (!email || !code) {
            return res.status(400).json({ error: 'Email и код обязательны' });
        }
        
        const result = await simpleAuth.verifyEmail(email, code);
        res.json(result);
        
    } catch (error) {
        console.error('Ошибка подтверждения email:', error);
        res.status(400).json({ error: error.message });
    }
});

// Вход
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email и пароль обязательны' });
        }
        
        const result = await simpleAuth.login(email, password);
        res.json(result);
        
    } catch (error) {
        console.error('Ошибка входа:', error);
        res.status(401).json({ error: error.message });
    }
});

// Выход
app.post('/api/auth/logout', async (req, res) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        
        if (token) {
            await simpleAuth.logout(token);
        }
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Ошибка выхода:', error);
        res.status(500).json({ error: error.message });
    }
});

// Использование кода для роли
app.post('/api/auth/use-role-code', async (req, res) => {
    try {
        const { code } = req.body;
        
        if (!code) {
            return res.status(400).json({ error: 'Код обязателен' });
        }
        
        if (!req.user) {
            return res.status(401).json({ error: 'Требуется авторизация' });
        }
        
        const result = await simpleAuth.useRoleCode(req.user.id, code);
        res.json(result);
        
    } catch (error) {
        console.error('Ошибка использования кода:', error);
        res.status(400).json({ error: error.message });
    }
});

// Получить профиль
app.get('/api/auth/profile', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ error: 'Требуется авторизация' });
        }
        
        const result = await simpleAuth.getProfile(req.user.id);
        res.json(result);
        
    } catch (error) {
        console.error('Ошибка получения профиля:', error);
        res.status(500).json({ error: error.message });
    }
});

// Проверка авторизации
app.get('/api/auth/check', async (req, res) => {
    res.json({
        authenticated: !!req.user,
        user: req.user
    });
});

// Создать коды для ролей (админская функция, только для разработки)
app.post('/api/auth/create-codes', async (req, res) => {
    try {
        // Простая защита - секретный ключ в запросе
        const { secret } = req.body;
        if (secret !== 'school2024') {
            return res.status(403).json({ error: 'Доступ запрещен' });
        }
        
        const result = await simpleAuth.createRoleCodes();
        res.json(result);
        
    } catch (error) {
        console.error('Ошибка создания кодов:', error);
        res.status(500).json({ error: error.message });
    }
});

// ========== Обновленные маршруты с авторизацией ==========

// Получить все идеи (остается публичным)
app.get('/api/ideas', async (req, res) => {
    try {
        const ideas = await db.getAllIdeas();
        
        // Добавляем информацию о том, может ли пользователь удалять/редактировать
        if (req.user) {
            const ideasWithPermissions = ideas.map(idea => ({
                ...idea,
                canDelete: req.user.role === 'moderator' || idea.author === req.user.name,
                canEdit: idea.author === req.user.name
            }));
            res.json(ideasWithPermissions);
        } else {
            res.json(ideas.map(idea => ({
                ...idea,
                canDelete: false,
                canEdit: false
            })));
        }
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Добавить новую идею (теперь с авторизацией)
app.post('/api/ideas', async (req, res) => {
    try {
        const { title, description } = req.body;
        
        if (!req.user) {
            return res.status(401).json({ error: 'Требуется авторизация' });
        }
        
        if (!title || !description) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }
        
        // Используем имя из профиля пользователя
        const result = await db.addIdea(title, description, req.user.name);
        
        // Если пользователь - контент-менеджер, идея сразу одобрена
        if (req.user.role === 'content_manager') {
            await db.pool.query(
                'UPDATE ideas SET status = ? WHERE id = ?',
                ['approved', result.id || result]
            );
        }
        
        res.json({ 
            success: true, 
            id: result.id || result,
            message: req.user.role === 'content_manager' ? 'Идея одобрена и опубликована' : 'Идея отправлена на модерацию'
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Удалить идею (только модераторы и авторы)
app.delete('/api/ideas/:id', async (req, res) => {
    try {
        const ideaId = parseInt(req.params.id);
        
        if (!req.user) {
            return res.status(401).json({ error: 'Требуется авторизация' });
        }
        
        // Получаем информацию об идее
        const idea = await new Promise((resolve, reject) => {
            db.pool.get(
                'SELECT author FROM ideas WHERE id = ?',
                [ideaId],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
        
        if (!idea) {
            return res.status(404).json({ error: 'Идея не найдена' });
        }
        
        // Проверяем права: модератор или автор идеи
        const isModerator = req.user.role === 'moderator';
        const isAuthor = idea.author === req.user.name;
        
        if (!isModerator && !isAuthor) {
            return res.status(403).json({ error: 'Недостаточно прав для удаления' });
        }
        
        // Удаляем идею
        await new Promise((resolve, reject) => {
            db.pool.run(
                'DELETE FROM ideas WHERE id = ?',
                [ideaId],
                function(err) {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
        
        // Также удаляем связанные комментарии и голоса
        await new Promise((resolve, reject) => {
            db.pool.run('DELETE FROM comments WHERE idea_id = ?', [ideaId], err => {
                if (err) reject(err);
                else resolve();
            });
        });
        
        await new Promise((resolve, reject) => {
            db.pool.run('DELETE FROM votes WHERE idea_id = ?', [ideaId], err => {
                if (err) reject(err);
                else resolve();
            });
        });
        
        res.json({ 
            success: true,
            message: 'Идея удалена'
        });
        
    } catch (error) {
        console.error('Ошибка удаления идеи:', error);
        res.status(500).json({ error: error.message });
    }
});

// Изменить статус идеи (для контент-менеджеров)
app.post('/api/ideas/:id/status', async (req, res) => {
    try {
        const ideaId = parseInt(req.params.id);
        const { status } = req.body; // 'approved', 'rejected', 'pending', 'featured'
        
        if (!req.user) {
            return res.status(401).json({ error: 'Требуется авторизация' });
        }
        
        // Только контент-менеджеры могут менять статус
        if (req.user.role !== 'content_manager') {
            return res.status(403).json({ error: 'Только контент-менеджеры могут менять статус идей' });
        }
        
        if (!['approved', 'rejected', 'pending', 'featured'].includes(status)) {
            return res.status(400).json({ error: 'Неверный статус' });
        }
        
        await new Promise((resolve, reject) => {
            db.pool.run(
                'UPDATE ideas SET status = ? WHERE id = ?',
                [status, ideaId],
                function(err) {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
        
        res.json({ 
            success: true,
            message: `Статус идеи изменен на: ${status}`
        });
        
    } catch (error) {
        console.error('Ошибка изменения статуса:', error);
        res.status(500).json({ error: error.message });
    }
});

// Получить идеи для модерации (только для модераторов)
app.get('/api/moderator/pending', async (req, res) => {
    try {
        if (!req.user || req.user.role !== 'moderator') {
            return res.status(403).json({ error: 'Только модераторы имеют доступ' });
        }
        
        const ideas = await new Promise((resolve, reject) => {
            db.pool.all(
                'SELECT * FROM ideas WHERE status = ? ORDER BY created_at DESC',
                ['pending'],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
        
        res.json(ideas);
        
    } catch (error) {
        console.error('Ошибка получения идей для модерации:', error);
        res.status(500).json({ error: error.message });
    }
});

// Получить статистику (для контент-менеджеров)
app.get('/api/content-manager/stats', async (req, res) => {
    try {
        if (!req.user || req.user.role !== 'content_manager') {
            return res.status(403).json({ error: 'Только контент-менеджеры имеют доступ' });
        }
        
        const stats = await new Promise((resolve, reject) => {
            db.pool.get(
                `SELECT 
                    COUNT(*) as total_ideas,
                    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_ideas,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_ideas,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_ideas,
                    SUM(CASE WHEN status = 'featured' THEN 1 ELSE 0 END) as featured_ideas,
                    COUNT(DISTINCT author) as unique_authors
                 FROM ideas`,
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
        
        res.json(stats);
        
    } catch (error) {
        console.error('Ошибка получения статистики:', error);
        res.status(500).json({ error: error.message });
    }
});

// Остальные существующие маршруты остаются без изменений
// Голосование, комментарии и т.д.

// Обработка ошибок
app.use((error, req, res, next) => {
    console.error('Глобальная ошибка:', error);
    res.status(500).json({ 
        error: 'Внутренняя ошибка сервера',
        message: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`🚀 Сервер запущен на порту ${PORT}`);
    console.log(`🌐 Сайт: http://localhost:${PORT}`);
    console.log(`📊 MongoDB: ${process.env.MONGODB_URI ? 'Настроен' : 'Используется локальная строка'}`);
});


