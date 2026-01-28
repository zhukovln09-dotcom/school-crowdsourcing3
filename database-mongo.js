// database-mongo.js - для MongoDB Atlas
const mongoose = require('mongoose');

// Строка подключения к MongoDB Atlas
const MONGODB_URI = process.env.MONGODB_URI || 
    'mongodb+srv://Leonid:yzF-UgN-teN-TQ8@cluster0.52cmiku.mongodb.net/?appName=Cluster0&serverSelectionTimeoutMS=5000&socketTimeoutMS=45000';

// Подключение к MongoDB
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('✅ Успешно подключено к MongoDB Atlas');
}).catch((error) => {
    console.error('❌ Ошибка подключения к MongoDB:', error.message);
    console.log('💡 Проверьте:');
    console.log('1. Правильный ли пароль в строке подключения?');
    console.log('2. Добавили ли IP 0.0.0.0/0 в Network Access?');
    console.log('3. Работает ли интернет?');
});

// Определяем схему для Идей
const ideaSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Название идеи обязательно'],
        minlength: [3, 'Название должно быть минимум 3 символа']
    },
    description: {
        type: String,
        required: [true, 'Описание идеи обязательно'],
        minlength: [10, 'Описание должно быть минимум 10 символов']
    },
    author: {
        type: String,
        required: [true, 'Автор обязателен'],
        default: 'Аноним'
    },
    votes: {
        type: Number,
        default: 0
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected', 'in_progress', 'completed'],
        default: 'pending'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Определяем схему для Комментариев
const commentSchema = new mongoose.Schema({
    ideaId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Idea',
        required: true
    },
    author: {
        type: String,
        required: true,
        default: 'Аноним'
    },
    text: {
        type: String,
        required: [true, 'Текст комментария обязателен'],
        minlength: [2, 'Комментарий должен быть минимум 2 символа']
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Определяем схему для Голосов
const voteSchema = new mongoose.Schema({
    ideaId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Idea',
        required: true
    },
    userIp: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Уникальный индекс для голосов (один человек - один голос)
voteSchema.index({ ideaId: 1, userIp: 1 }, { unique: true });

// Создаем модели на основе схем
const Idea = mongoose.model('Idea', ideaSchema);
const Comment = mongoose.model('Comment', commentSchema);
const Vote = mongoose.model('Vote', voteSchema);

class Database {
    constructor() {
        console.log('📊 Инициализация MongoDB базы данных...');
        this.Idea = Idea;
        this.Comment = Comment;
        this.Vote = Vote;
    }

    // Получить все идеи с количеством голосов и комментариев
    async getAllIdeas() {
        try {
            const ideas = await Idea.aggregate([
                {
                    $lookup: {
                        from: 'comments',
                        localField: '_id',
                        foreignField: 'ideaId',
                        as: 'comments'
                    }
                },
                {
                    $lookup: {
                        from: 'votes',
                        localField: '_id',
                        foreignField: 'ideaId',
                        as: 'votes'
                    }
                },
                {
                    $addFields: {
                        comment_count: { $size: '$comments' },
                        vote_count: { $size: '$votes' }
                    }
                },
                {
                    $project: {
                        comments: 0,
                        votes: 0,
                        __v: 0
                    }
                },
                {
                    $sort: {
                        votes: -1,
                        createdAt: -1
                    }
                }
            ]);

            // Преобразуем в формат похожий на SQLite
            return ideas.map(idea => ({
                id: idea._id,
                title: idea.title,
                description: idea.description,
                author: idea.author,
                votes: idea.votes,
                status: idea.status,
                created_at: idea.createdAt,
                comment_count: idea.comment_count,
                vote_count: idea.vote_count
            }));

        } catch (error) {
            console.error('❌ Ошибка получения идей:', error);
            throw error;
        }
    }

    // Добавить новую идею
    async addIdea(title, description, author) {
        try {
            const idea = new Idea({
                title,
                description,
                author: author || 'Аноним'
            });

            const savedIdea = await idea.save();
            return { success: true, id: savedIdea._id };

        } catch (error) {
            console.error('❌ Ошибка добавления идеи:', error);
            
            // Более понятные ошибки для пользователя
            if (error.errors?.title) {
                throw new Error(error.errors.title.message);
            }
            if (error.errors?.description) {
                throw new Error(error.errors.description.message);
            }
            
            throw new Error('Не удалось добавить идею');
        }
    }

    // Проголосовать за идею
    async voteForIdea(ideaId, userIp) {
        const session = await mongoose.startSession();
        
        try {
            session.startTransaction();

            // Проверяем существование идеи
            const idea = await Idea.findById(ideaId).session(session);
            if (!idea) {
                throw new Error('Идея не найдена');
            }

            // Пытаемся добавить голос (уникальность проверяется на уровне БД)
            try {
                const vote = new Vote({
                    ideaId,
                    userIp
                });
                await vote.save({ session });
            } catch (error) {
                if (error.code === 11000) { // Код дубликата в MongoDB
                    throw new Error('Вы уже голосовали за эту идею');
                }
                throw error;
            }

            // Увеличиваем счетчик голосов
            idea.votes += 1;
            await idea.save({ session });

            await session.commitTransaction();
            return { success: true };

        } catch (error) {
            await session.abortTransaction();
            throw error;
            
        } finally {
            session.endSession();
        }
    }

    // Добавить комментарий
    async addComment(ideaId, author, text) {
        try {
            // Проверяем существование идеи
            const idea = await Idea.findById(ideaId);
            if (!idea) {
                throw new Error('Идея не найдена');
            }

            const comment = new Comment({
                ideaId,
                author: author || 'Аноним',
                text
            });

            const savedComment = await comment.save();
            return { success: true, id: savedComment._id };

        } catch (error) {
            console.error('❌ Ошибка добавления комментария:', error);
            
            if (error.errors?.text) {
                throw new Error(error.errors.text.message);
            }
            
            throw new Error('Не удалось добавить комментарий');
        }
    }

    // Получить комментарии для идеи
    async getComments(ideaId) {
        try {
            const comments = await Comment.find({ ideaId })
                .sort({ createdAt: 1 })
                .lean(); // Возвращаем простые объекты
            
            // Преобразуем в формат похожий на SQLite
            return comments.map(comment => ({
                id: comment._id,
                idea_id: comment.ideaId,
                author: comment.author,
                text: comment.text,
                created_at: comment.createdAt
            }));

        } catch (error) {
            console.error('❌ Ошибка получения комментариев:', error);
            throw error;
        }
    }

    // Получить статистику
    async getStats() {
        try {
            const ideasCount = await Idea.countDocuments();
            const commentsCount = await Comment.countDocuments();
            const votesCount = await Vote.countDocuments();
            
            return {
                ideas: ideasCount,
                comments: commentsCount,
                votes: votesCount
            };
        } catch (error) {
            console.error('❌ Ошибка получения статистики:', error);
            return { ideas: 0, comments: 0, votes: 0 };
        }
    }

    // Тест подключения
    async testConnection() {
        try {
            await mongoose.connection.db.admin().ping();
            return { connected: true };
        } catch (error) {
            return { connected: false, error: error.message };
        }
    }

    // Очистить базу данных (только для тестирования!)
    async clearDatabase() {
        if (process.env.NODE_ENV !== 'development') {
            throw new Error('Очистка БД разрешена только в режиме разработки');
        }
        
        await Idea.deleteMany({});
        await Comment.deleteMany({});
        await Vote.deleteMany({});
        
        console.log('🗑️ База данных очищена');
        return { success: true };
    }
}

// Экспортируем экземпляр базы данных
const database = new Database();
module.exports = database;
