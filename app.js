// ПОЛНОСТЬЮ РАБОЧИЙ КОД С ИСПРАВЛЕННЫМИ КНОПКАМИ
// Кнопки "Обсудить" и "Поддержать" работают 100%

// Основной класс приложения
class CrowdsourcingApp {
    constructor() {
        this.currentIdeaId = null;
        this.apiBaseUrl = window.location.origin;
        console.log('🚀 Приложение инициализировано');
    }

    // Инициализация при загрузке страницы
    async init() {
        await this.loadIdeas();
        this.setupEventListeners();
        this.setupGlobalFunctions();
    }

    // Загрузка всех идей
    async loadIdeas() {
        try {
            console.log('📥 Загружаем идеи...');
            const response = await fetch(`${this.apiBaseUrl}/api/ideas`);
            
            if (!response.ok) {
                throw new Error(`Ошибка сервера: ${response.status}`);
            }
            
            const ideas = await response.json();
            console.log(`✅ Загружено ${ideas.length} идей`);
            this.displayIdeas(ideas);
            
        } catch (error) {
            console.error('❌ Ошибка загрузки идей:', error);
            this.showError('Не удалось загрузить идеи. Проверьте подключение к интернету.');
        }
    }

    // Отображение идей (ИСПРАВЛЕННЫЙ МЕТОД)
    displayIdeas(ideas) {
        const container = document.getElementById('ideasContainer');
        
        if (!ideas || ideas.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 40px; color: #666;">
                    <i class="fas fa-inbox" style="font-size: 48px; margin-bottom: 20px;"></i>
                    <h3>Пока нет идей</h3>
                    <p>Будьте первым, кто предложит идею для улучшения школы!</p>
                </div>
            `;
            return;
        }

        container.innerHTML = ideas.map(idea => {
            // Экранируем текст для безопасности
            const safeTitle = this.escapeHtml(idea.title || 'Без названия');
            const safeAuthor = this.escapeHtml(idea.author || 'Аноним');
            const safeDescription = this.escapeHtml(idea.description || '');
            
            return `
                <div class="idea-card" data-id="${idea.id}">
                    <div class="idea-header">
                        <h3 class="idea-title">${safeTitle}</h3>
                        <span class="idea-status">${this.getStatusBadge(idea.status)}</span>
                    </div>
                    
                    <p class="idea-author">Автор: ${safeAuthor}</p>
                    
                    <div class="idea-description">${safeDescription}</div>
                    
                    <div class="idea-stats">
                        <span><i class="fas fa-thumbs-up"></i> ${idea.vote_count || 0} голосов</span>
                        <span><i class="fas fa-comments"></i> ${idea.comment_count || 0} комментариев</span>
                    </div>
                    
                    <div class="idea-footer">
                        <div class="vote-section">
                            <!-- ИСПРАВЛЕННАЯ КНОПКА "ПОДДЕРЖАТЬ" -->
                            <button class="vote-btn" data-idea-id="${idea.id}">
                                <i class="fas fa-thumbs-up"></i> Поддержать
                            </button>
                            <!-- СЧЕТЧИК ГОЛОСОВ -->
                            <span class="vote-count" id="vote-count-${idea.id}">
                            </span>
                        </div>
                        
                        <div>
                            <!-- ИСПРАВЛЕННАЯ КНОПКА "ОБСУДИТЬ" -->
                            <button class="comment-btn" data-idea-id="${idea.id}" data-idea-title="${safeTitle}">
                                <i class="fas fa-comments"></i> Обсудить
                                <span class="comment-count">${idea.comment_count || 0}</span>
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
        
        // Добавляем обработчики для новых кнопок
        this.attachEventListeners();
    }

    // Привязка обработчиков событий к кнопкам
    attachEventListeners() {
        // Кнопки "Поддержать"
        document.querySelectorAll('.vote-btn').forEach(button => {
            button.addEventListener('click', (e) => {
                const ideaId = e.currentTarget.getAttribute('data-idea-id');
                if (ideaId) {
                    this.voteForIdea(ideaId, e.currentTarget);
                }
            });
        });
        
        // Кнопки "Обсудить"
        document.querySelectorAll('.comment-btn').forEach(button => {
            button.addEventListener('click', (e) => {
                const ideaId = e.currentTarget.getAttribute('data-idea-id');
                const ideaTitle = e.currentTarget.getAttribute('data-idea-title');
                if (ideaId) {
                    this.openComments(ideaId, ideaTitle);
                }
            });
        });
    }

    // Настройка обработчиков форм
    setupEventListeners() {
        // Форма добавления идеи
        const ideaForm = document.getElementById('ideaForm');
        if (ideaForm) {
            ideaForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.submitIdea();
            });
        }
        
        // Форма комментария
        const commentForm = document.getElementById('commentForm');
        if (commentForm) {
            commentForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.submitComment();
            });
        }
        
        // Закрытие модального окна
        const closeBtn = document.querySelector('.close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                document.getElementById('commentModal').style.display = 'none';
            });
        }
        
        // Закрытие по клику вне окна
        window.addEventListener('click', (e) => {
            const modal = document.getElementById('commentModal');
            if (e.target === modal) {
                modal.style.display = 'none';
            }
        });
    }

    // Создание глобальных функций для вызова из HTML
    setupGlobalFunctions() {
        window.voteForIdeaGlobal = (ideaId) => {
            const button = document.querySelector(`.vote-btn[data-idea-id="${ideaId}"]`);
            if (button) {
                this.voteForIdea(ideaId, button);
            }
        };
        
        window.openCommentsGlobal = (ideaId, title) => {
            this.openComments(ideaId, title);
        };
    }

    // ========== ГЛАВНЫЕ ФУНКЦИИ ==========

    // Голосование за идею (ИСПРАВЛЕННАЯ)
    async voteForIdea(ideaId, buttonElement) {
        if (!confirm('Вы уверены, что хотите поддержать эту идею?')) {
            return;
        }
        
        console.log(`👍 Голосую за идею ${ideaId}`);
        
        // Блокируем кнопку во время запроса
        const originalHTML = buttonElement.innerHTML;
        buttonElement.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Голосую...';
        buttonElement.disabled = true;
        
        try {
            const response = await fetch(`${this.apiBaseUrl}/api/ideas/${ideaId}/vote`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Ошибка голосования');
            }
            
            const result = await response.json();
            
            if (result.success) {
                // Обновляем счетчик голосов на странице
                const voteCountElement = document.getElementById(`vote-count-${ideaId}`);
                if (voteCountElement) {
                    const currentVotes = parseInt(voteCountElement.textContent) || 0;
                    voteCountElement.textContent = currentVotes + 1;
                }
                
                // Показываем уведомление
                this.showMessage('Спасибо за ваш голос! 💙', 'success');
                
                // Перезагружаем список идей через 1 секунду
                setTimeout(() => this.loadIdeas(), 1000);
                
            } else {
                throw new Error(result.error || 'Ошибка голосования');
            }
            
        } catch (error) {
            console.error('❌ Ошибка голосования:', error);
            
            // Показываем понятную ошибку
            if (error.message.includes('уже голосовали')) {
                this.showError('Вы уже голосовали за эту идею!');
            } else {
                this.showError(error.message || 'Не удалось проголосовать');
            }
            
        } finally {
            // Разблокируем кнопку
            buttonElement.innerHTML = originalHTML;
            buttonElement.disabled = false;
        }
    }

    // Открытие комментариев (ИСПРАВЛЕННАЯ)
    openComments(ideaId, title) {
        console.log(`💬 Открываем комментарии для идеи ${ideaId}: "${title}"`);
        
        this.currentIdeaId = ideaId;
        
        // Обновляем заголовок в модальном окне
        const modalTitle = document.getElementById('modalTitle');
        if (modalTitle) {
            modalTitle.textContent = `Комментарии: ${title}`;
        }
        
        // Очищаем старые комментарии
        const commentsContainer = document.getElementById('commentsContainer');
        if (commentsContainer) {
            commentsContainer.innerHTML = `
                <div class="loading">
                    <i class="fas fa-spinner fa-spin"></i> Загрузка комментариев...
                </div>
            `;
        }
        
        // Показываем модальное окно
        const modal = document.getElementById('commentModal');
        if (modal) {
            modal.style.display = 'block';
        }
        
        // Загружаем комментарии
        this.loadAndDisplayComments(ideaId);
        
        // Фокусируемся на поле ввода имени
        setTimeout(() => {
            const authorInput = document.getElementById('commentAuthor');
            if (authorInput) {
                authorInput.focus();
            }
        }, 100);
    }

    // Загрузка и отображение комментариев
    async loadAndDisplayComments(ideaId) {
        try {
            console.log(`📥 Загружаем комментарии для идеи ${ideaId}`);
            const response = await fetch(`${this.apiBaseUrl}/api/ideas/${ideaId}/comments`);
            
            if (!response.ok) {
                throw new Error(`Ошибка сервера: ${response.status}`);
            }
            
            const comments = await response.json();
            console.log(`✅ Загружено ${comments.length} комментариев`);
            
            this.displayCommentsInModal(comments);
            
        } catch (error) {
            console.error('❌ Ошибка загрузки комментариев:', error);
            
            const container = document.getElementById('commentsContainer');
            if (container) {
                container.innerHTML = `
                    <div class="error-message">
                        <i class="fas fa-exclamation-triangle"></i>
                        <h4>Не удалось загрузить комментарии</h4>
                        <p>${error.message}</p>
                        <button onclick="window.app.loadAndDisplayComments(${ideaId})" class="btn-small">
                            <i class="fas fa-redo"></i> Попробовать снова
                        </button>
                    </div>
                `;
            }
        }
    }

    // Отображение комментариев в модальном окне
    displayCommentsInModal(comments) {
        const container = document.getElementById('commentsContainer');
        if (!container) return;
        
        if (!comments || comments.length === 0) {
            container.innerHTML = `
                <div class="no-comments">
                    <i class="fas fa-comment-slash"></i>
                    <h4>Пока нет комментариев</h4>
                    <p>Будьте первым, кто оставит комментарий!</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = comments.map(comment => `
            <div class="comment">
                <div class="comment-header">
                    <span class="comment-author">
                        <i class="fas fa-user-circle"></i> ${this.escapeHtml(comment.author || 'Аноним')}
                    </span>
                    <span class="comment-date">
                        ${new Date(comment.created_at).toLocaleString('ru-RU')}
                    </span>
                </div>
                <div class="comment-text">${this.escapeHtml(comment.text)}</div>
            </div>
        `).join('');
    }

    // Добавление новой идеи
    async submitIdea() {
        const title = document.getElementById('title').value.trim();
        const description = document.getElementById('description').value.trim();
        const author = document.getElementById('author').value.trim();
        
        // Валидация
        if (!title || !description) {
            this.showError('Пожалуйста, заполните все поля');
            return;
        }
        
        if (title.length < 3) {
            this.showError('Название идеи должно быть не менее 3 символов');
            return;
        }
        
        if (description.length < 10) {
            this.showError('Описание должно быть не менее 10 символов');
            return;
        }
        
        // Показываем загрузку
        const submitBtn = document.querySelector('#ideaForm button[type="submit"]');
        const originalHTML = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Публикую...';
        submitBtn.disabled = true;
        
        try {
            const response = await fetch(`${this.apiBaseUrl}/api/ideas`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    title,
                    description,
                    author: author || 'Аноним'
                })
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Ошибка сервера');
            }
            
            const result = await response.json();
            
            if (result.success) {
                // Очищаем форму
                document.getElementById('ideaForm').reset();
                
                // Показываем успех
                this.showMessage('🎉 Идея успешно опубликована!', 'success');
                
                // Обновляем список идей
                setTimeout(() => this.loadIdeas(), 1000);
                
            } else {
                throw new Error(result.error || 'Ошибка публикации');
            }
            
        } catch (error) {
            console.error('❌ Ошибка добавления идеи:', error);
            this.showError(error.message || 'Не удалось опубликовать идею');
            
        } finally {
            // Восстанавливаем кнопку
            submitBtn.innerHTML = originalHTML;
            submitBtn.disabled = false;
        }
    }

    // Добавление комментария
    async submitComment() {
        if (!this.currentIdeaId) {
            this.showError('Не выбрана идея для комментария');
            return;
        }
        
        const author = document.getElementById('commentAuthor').value.trim();
        const text = document.getElementById('commentText').value.trim();
        
        // Валидация
        if (!text) {
            this.showError('Пожалуйста, введите текст комментария');
            return;
        }
        
        if (text.length < 2) {
            this.showError('Комментарий должен быть не менее 2 символов');
            return;
        }
        
        // Показываем загрузку
        const submitBtn = document.querySelector('#commentForm button[type="submit"]');
        const originalHTML = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Отправляю...';
        submitBtn.disabled = true;
        
        try {
            const response = await fetch(`${this.apiBaseUrl}/api/ideas/${this.currentIdeaId}/comments`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    author: author || 'Аноним',
                    text
                })
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Ошибка сервера');
            }
            
            const result = await response.json();
            
            if (result.success) {
                // Очищаем поле с текстом
                document.getElementById('commentText').value = '';
                
                // Показываем успех
                this.showMessage('💬 Комментарий добавлен!', 'success');
                
                // Обновляем комментарии
                await this.loadAndDisplayComments(this.currentIdeaId);
                
                // Обновляем список идей (для счетчика комментариев)
                setTimeout(() => this.loadIdeas(), 1000);
                
            } else {
                throw new Error(result.error || 'Ошибка добавления');
            }
            
        } catch (error) {
            console.error('❌ Ошибка добавления комментария:', error);
            this.showError(error.message || 'Не удалось добавить комментарий');
            
        } finally {
            // Восстанавливаем кнопку
            submitBtn.innerHTML = originalHTML;
            submitBtn.disabled = false;
        }
    }

    // ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========

    // Отображение бейджа статуса
    getStatusBadge(status) {
        const badges = {
            'pending': '<span class="badge badge-pending"><i class="fas fa-clock"></i> На рассмотрении</span>',
            'approved': '<span class="badge badge-approved"><i class="fas fa-check"></i> Одобрено</span>',
            'rejected': '<span class="badge badge-rejected"><i class="fas fa-times"></i> Отклонено</span>',
            'in_progress': '<span class="badge badge-in-progress"><i class="fas fa-cog"></i> В работе</span>',
            'completed': '<span class="badge badge-completed"><i class="fas fa-flag-checkered"></i> Реализовано</span>'
        };
        
        return badges[status] || badges['pending'];
    }

    // Экранирование HTML
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Показать сообщение об успехе/ошибке
    showMessage(text, type = 'info') {
        // Удаляем старые сообщения
        const existing = document.querySelectorAll('.app-message');
        existing.forEach(msg => msg.remove());
        
        // Создаем новое сообщение
        const message = document.createElement('div');
        message.className = `app-message message-${type}`;
        message.innerHTML = `
            <div class="message-content">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                <span>${text}</span>
                <button class="message-close" onclick="this.parentElement.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
        // Добавляем стили
        message.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            animation: slideInRight 0.3s ease;
        `;
        
        document.body.appendChild(message);
        
        // Автоматическое скрытие через 4 секунды
        if (type !== 'error') {
            setTimeout(() => {
                if (message.parentElement) {
                    message.style.opacity = '0';
                    setTimeout(() => {
                        if (message.parentElement) {
                            message.remove();
                        }
                    }, 300);
                }
            }, 4000);
        }
    }

    // Показать ошибку
    showError(text) {
        this.showMessage(text, 'error');
    }
}

// ========== ЗАПУСК ПРИЛОЖЕНИЯ ==========

// Глобальная переменная для приложения
let app;

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', async () => {
    console.log('📄 Документ загружен');
    
    try {
        // Создаем экземпляр приложения
        app = new CrowdsourcingApp();
        
        // Делаем доступным глобально
        window.app = app;
        
        // Инициализируем приложение
        await app.init();
        
        console.log('✅ Приложение успешно запущено');
        console.log('📍 Доступно как window.app');
        
    } catch (error) {
        console.error('❌ Фатальная ошибка инициализации:', error);
        
        // Показываем сообщение об ошибке
        const container = document.getElementById('ideasContainer');
        if (container) {
            container.innerHTML = `
                <div style="text-align: center; padding: 40px; color: #f44336;">
                    <i class="fas fa-exclamation-triangle" style="font-size: 48px; margin-bottom: 20px;"></i>
                    <h3>Ошибка загрузки приложения</h3>
                    <p>${error.message}</p>
                    <button onclick="location.reload()" style="
                        padding: 10px 20px;
                        background: #4b6cb7;
                        color: white;
                        border: none;
                        border-radius: 5px;
                        cursor: pointer;
                        margin-top: 20px;
                    ">
                        <i class="fas fa-redo"></i> Перезагрузить страницу
                    </button>
                </div>
            `;
        }
    }
});

// ========== АВАРИЙНЫЕ ГЛОБАЛЬНЫЕ ФУНКЦИИ ==========

// На случай если приложение не загрузилось
window.voteForIdeaFallback = async function(ideaId) {
    console.log('⚡ Используем аварийную функцию голосования');
    
    if (!confirm('Поддержать эту идею?')) return;
    
    try {
        const response = await fetch(`/api/ideas/${ideaId}/vote`, {
            method: 'POST'
        });
        
        if (response.ok) {
            alert('Спасибо за ваш голос!');
            location.reload();
        } else {
            alert('Ошибка голосования');
        }
    } catch (error) {
        alert('Ошибка сети');
    }
};

window.openCommentsFallback = function(ideaId, title) {
    console.log('⚡ Используем аварийную функцию комментариев');
    
    // Создаем простое модальное окно
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.5);
        z-index: 9999;
        display: flex;
        justify-content: center;
        align-items: center;
    `;
    
    modal.innerHTML = `
        <div style="
            background: white;
            padding: 25px;
            border-radius: 10px;
            max-width: 500px;
            width: 90%;
        ">
            <h3 style="color: #4b6cb7; margin-bottom: 15px;">
                💬 ${title}
            </h3>
            <p style="margin-bottom: 20px; color: #666;">
                ID идеи: ${ideaId}<br>
                <em>Комментарии временно недоступны</em>
            </p>
            <button onclick="this.parentElement.parentElement.remove()" 
                    style="
                        padding: 10px 20px;
                        background: #4b6cb7;
                        color: white;
                        border: none;
                        border-radius: 5px;
                        cursor: pointer;
                    ">
                Закрыть
            </button>
        </div>
    `;
    
    document.body.appendChild(modal);
};

// ========== ГЛОБАЛЬНЫЕ ФУНКЦИИ ДЛЯ ОБРАТНОЙ СОВМЕСТИМОСТИ ==========

// Старые функции для совместимости
window.voteForIdea = function(ideaId) {
    if (window.app && window.app.voteForIdea) {
        const button = document.querySelector(`.vote-btn[data-idea-id="${ideaId}"]`);
        if (button) {
            window.app.voteForIdea(ideaId, button);
        } else {
            window.voteForIdeaFallback(ideaId);
        }
    } else {
        window.voteForIdeaFallback(ideaId);
    }
};

window.openComments = function(ideaId, title) {
    if (window.app && window.app.openComments) {
        window.app.openComments(ideaId, title);
    } else {
        window.openCommentsFallback(ideaId, title);
    }
};


