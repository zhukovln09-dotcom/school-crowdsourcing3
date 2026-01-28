// simple-auth.js - минимальная авторизация без сложных зависимостей
const crypto = require('crypto');
const authDb = require('./auth-database.js');

class SimpleAuth {
    constructor() {
        console.log('Простая авторизация инициализирована');
    }

    // Генерация случайного кода
    generateCode(length = 6) {
        return crypto.randomBytes(Math.ceil(length / 2))
            .toString('hex')
            .slice(0, length)
            .toUpperCase();
    }

    // Простая хэш-функция (для демо, в продакшене использовать bcrypt)
    simpleHash(password) {
        return crypto.createHash('sha256').update(password).digest('hex');
    }

    // Генерация токена
    generateToken() {
        return crypto.randomBytes(32).toString('hex');
    }

    // Регистрация
    async register(email, password, name) {
        try {
            // Проверяем, нет ли уже пользователя
            const existing = await authDb.findUserByEmail(email);
            if (existing) {
                throw new Error('Пользователь с таким email уже существует');
            }

            // Хэшируем пароль
            const passwordHash = this.simpleHash(password);
            
            // Генерируем код подтверждения
            const verificationCode = this.generateCode(6);
            
            // Создаем пользователя
            const user = await authDb.createUser(email, passwordHash, name);
            
            // Сохраняем код подтверждения
            await authDb.setVerificationCode(email, verificationCode);
            
            // В реальном приложении здесь отправляем email
            console.log(`Код подтверждения для ${email}: ${verificationCode}`);
            
            return {
                success: true,
                userId: user.id,
                verificationCode: verificationCode, // В демо-режиме возвращаем код
                message: 'Регистрация успешна. Проверьте email для подтверждения.'
            };
            
        } catch (error) {
            console.error('Ошибка регистрации:', error);
            throw error;
        }
    }

    // Подтверждение email
    async verifyEmail(email, code) {
        try {
            const result = await authDb.updateUserVerification(email, code);
            
            if (result.changes === 0) {
                throw new Error('Неверный код подтверждения');
            }
            
            return {
                success: true,
                message: 'Email успешно подтвержден'
            };
            
        } catch (error) {
            console.error('Ошибка подтверждения email:', error);
            throw error;
        }
    }

    // Вход
    async login(email, password) {
        try {
            // Ищем пользователя
            const user = await authDb.findUserByEmail(email);
            if (!user) {
                throw new Error('Неверный email или пароль');
            }
            
            // Проверяем пароль
            const passwordHash = this.simpleHash(password);
            if (passwordHash !== user.password) {
                throw new Error('Неверный email или пароль');
            }
            
            // Проверяем подтверждение email
            if (!user.email_verified) {
                throw new Error('Email не подтвержден');
            }
            
            // Генерируем токен
            const token = this.generateToken();
            const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 дней
            
            // Создаем сессию
            await authDb.createSession(user.id, token, expiresAt);
            
            // Обновляем время последнего входа
            await authDb.updateLastLogin(user.id);
            
            return {
                success: true,
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    role: user.role
                }
            };
            
        } catch (error) {
            console.error('Ошибка входа:', error);
            throw error;
        }
    }

    // Проверка токена
    async authenticate(token) {
        try {
            if (!token) {
                return { authenticated: false };
            }
            
            const session = await authDb.findSession(token);
            if (!session) {
                return { authenticated: false };
            }
            
            return {
                authenticated: true,
                user: {
                    id: session.user_id,
                    email: session.email,
                    name: session.name,
                    role: session.role
                }
            };
            
        } catch (error) {
            console.error('Ошибка аутентификации:', error);
            return { authenticated: false };
        }
    }

    // Выход
    async logout(token) {
        try {
            await authDb.deleteSession(token);
            return { success: true };
        } catch (error) {
            console.error('Ошибка выхода:', error);
            throw error;
        }
    }

    // Использование кода для получения роли
    async useRoleCode(userId, code) {
        try {
            // Ищем код
            const accessCode = await authDb.findAccessCode(code);
            if (!accessCode) {
                throw new Error('Неверный или просроченный код');
            }
            
            // Обновляем роль пользователя
            await authDb.updateUserRole(userId, accessCode.role);
            
            // Помечаем код как использованный
            await authDb.useAccessCode(code, userId);
            
            return {
                success: true,
                role: accessCode.role,
                message: `Теперь у вас роль: ${accessCode.role === 'moderator' ? 'модератор' : 'контент-менеджер'}`
            };
            
        } catch (error) {
            console.error('Ошибка использования кода:', error);
            throw error;
        }
    }

    // Создание кодов для ролей (админ-функция)
    async createRoleCodes() {
        try {
            // Создаем код для модератора
            const moderatorCode = this.generateCode(8);
            await authDb.createAccessCode(moderatorCode, 'moderator');
            
            // Создаем код для контент-менеджера
            const contentManagerCode = this.generateCode(8);
            await authDb.createAccessCode(contentManagerCode, 'content_manager');
            
            console.log('Коды созданы (сохраните их!):');
            console.log('Модератор:', moderatorCode);
            console.log('Контент-менеджер:', contentManagerCode);
            
            return {
                success: true,
                codes: {
                    moderator: moderatorCode,
                    content_manager: contentManagerCode
                }
            };
            
        } catch (error) {
            console.error('Ошибка создания кодов:', error);
            throw error;
        }
    }

    // Получить профиль пользователя
    async getProfile(userId) {
        try {
            const user = await authDb.findUserById(userId);
            if (!user) {
                throw new Error('Пользователь не найден');
            }
            
            return {
                success: true,
                user
            };
            
        } catch (error) {
            console.error('Ошибка получения профиля:', error);
            throw error;
        }
    }
}

module.exports = new SimpleAuth();
