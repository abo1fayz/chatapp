require('dotenv').config();
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const http = require('http');
const bcrypt = require('bcrypt');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;

const { User } = require('./models/User');
const { Message } = require('./models/Message');
const { Friendship } = require('./models/Friendship');

const app = express();
const server = http.createServer(app);

// --- MongoDB Connection ---
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/chat-app', { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
})
.then(() => console.log('✅ MongoDB connected successfully'))
.catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
});

// --- Cloudinary Configuration ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// --- Middleware Setup ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// --- Session Configuration ---
const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET || 'chat-app-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/chat-app',
        ttl: 14 * 24 * 60 * 60 // 14 يوم
    }),
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000, // 24 ساعة
        httpOnly: true,
        secure: false,
        sameSite: 'lax'
    }
});
app.use(sessionMiddleware);

// --- Middleware لتتبع الجلسة ---
app.use((req, res, next) => {
    console.log('🔍 حالة الجلسة:', {
        sessionId: req.sessionID?.substring(0, 10) + '...',
        userId: req.session.userId,
        username: req.session.username,
        isAdmin: req.session.isAdmin,
        path: req.path
    });
    next();
});

// --- View Engine Setup ---
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- File Upload Configuration ---
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// --- Helper Functions ---
app.locals.getTimeAgo = function(date) {
    if (!date) return 'غير معروف';
    
    const now = new Date();
    const diff = now - new Date(date);
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (minutes < 1) return 'الآن';
    if (minutes < 60) return `منذ ${minutes} دقيقة`;
    if (hours < 24) return `منذ ${hours} ساعة`;
    if (days < 7) return `منذ ${days} يوم`;
    return new Date(date).toLocaleDateString('ar-SA');
};

app.locals.isUserOnline = function(lastSeen) {
    if (!lastSeen) return false;
    return Date.now() - new Date(lastSeen).getTime() < 5 * 60 * 1000; // 5 minutes
};

// --- Authentication Middleware ---
function requireLogin(req, res, next) {
    console.log('🔐 التحقق من المصادقة:', {
        path: req.path,
        hasSession: !!req.session.userId,
        userId: req.session.userId
    });
    
    if (!req.session.userId) {
        console.log('❌ لم يتم المصادقة، التوجيه إلى /login');
        return res.redirect('/login');
    }
    next();
}

function redirectIfLoggedIn(req, res, next) {
    console.log('🔍 التحقق من وجود جلسة نشطة:', {
        path: req.path,
        hasSession: !!req.session.userId
    });
    
    if (req.session.userId) {
        console.log('✅ يوجد جلسة نشطة، التوجيه إلى / (الأصدقاء)');
        return res.redirect('/');
    }
    next();
}

// --- Admin Configuration ---
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Middleware للتحقق من صلاحيات المسؤول
function requireAdmin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    
    if (!req.session.isAdmin) {
        return res.status(403).render('error', {
            message: 'ليس لديك صلاحيات للوصول إلى هذه الصفحة',
            title: 'صلاحيات غير كافية'
        });
    }
    next();
}

// --- Routes ---

// الصفحة الرئيسية - الآن تعرض الأصدقاء
app.get('/', requireLogin, async (req, res) => {
    try {
        console.log('🏠 الصفحة الرئيسية - تحميل الأصدقاء');
        
        const friends = await Friendship.find({
            $or: [
                { requester: req.session.userId, status: 'accepted' },
                { recipient: req.session.userId, status: 'accepted' }
            ]
        })
        .populate('requester', 'username avatarUrl lastSeen')
        .populate('recipient', 'username avatarUrl lastSeen')
        .sort({ createdAt: -1 })
        .lean();

        const friendList = await Promise.all(friends.map(async (f) => {
            const friend = f.requester._id.toString() === req.session.userId.toString() ? 
                f.recipient : f.requester;

            const unreadCount = await Message.countDocuments({
                userId: friend._id,
                toUserId: req.session.userId,
                read: false
            });

            console.log(`📊 عدد الرسائل غير المقروءة من ${friend.username}: ${unreadCount}`);

            return {
                _id: friend._id,
                username: friend.username,
                avatarUrl: friend.avatarUrl,
                lastSeen: friend.lastSeen,
                unreadCount: unreadCount
            };
        }));

        res.render('friends', { 
            friends: friendList,
            username: req.session.username,
            avatarUrl: req.session.avatarUrl,
            userId: req.session.userId,
            title: 'الأصدقاء'
        });
        
    } catch (error) {
        console.error('Error loading friends page:', error);
        res.status(500).render('error', { 
            message: 'حدث خطأ في تحميل الصفحة الرئيسية',
            title: 'خطأ'
        });
    }
});

// صفحة التسجيل الأولى
app.get('/register', redirectIfLoggedIn, (req, res) => {
    res.render('index', { 
        message: null,
        title: 'مرحباً في تطبيق الدردشة'
    });
});

// التحقق من اسم المستخدم
app.post('/check-username', redirectIfLoggedIn, async (req, res) => {
    try {
        const { username } = req.body;
        
        if (!username || username.trim().length < 3) {
            return res.render('index', { 
                message: 'اسم المستخدم يجب أن يكون 3 أحرف على الأقل',
                title: 'مرحباً في تطبيق الدردشة'
            });
        }

        const trimmedUsername = username.trim();
        const existingUser = await User.findOne({ 
            username: new RegExp(`^${trimmedUsername}$`, 'i') 
        });

        if (existingUser) {
            return res.render('index', { 
                message: 'اسم المستخدم مستخدم بالفعل، الرجاء اختيار اسم آخر',
                title: 'مرحباً في تطبيق الدردشة'
            });
        }

        req.session.pendingUsername = trimmedUsername;
        res.redirect('/set-password');
        
    } catch (error) {
        console.error('Error checking username:', error);
        res.render('index', { 
            message: 'حدث خطأ أثناء التحقق من اسم المستخدم',
            title: 'مرحباً في تطبيق الدردشة'
        });
    }
});

// صفحة إعداد كلمة السر
app.get('/set-password', redirectIfLoggedIn, (req, res) => {
    if (!req.session.pendingUsername) {
        return res.redirect('/register');
    }
    
    res.render('password', { 
        username: req.session.pendingUsername, 
        message: null 
    });
});

// عملية التسجيل
app.post('/register', redirectIfLoggedIn, upload.single('avatar'), async (req, res) => {
    try {
        console.log('🚀 بدء عملية التسجيل...');
        const username = req.session.pendingUsername;
        
        if (!username) {
            console.log('❌ لا يوجد اسم مستخدم في الجلسة');
            return res.redirect('/register');
        }

        const { password } = req.body;
        
        if (!password || password.length < 4) {
            return res.render('password', { 
                username, 
                message: 'كلمة السر يجب أن تكون 4 أحرف على الأقل' 
            });
        }

        let avatarUrl = null;
        
        if (req.file) {
            try {
                const uploadResult = await new Promise((resolve, reject) => {
                    const stream = cloudinary.uploader.upload_stream(
                        { 
                            folder: 'chat-app/avatars',
                            transformation: [
                                { width: 200, height: 200, crop: 'fill' },
                                { quality: 'auto' },
                                { format: 'webp' }
                            ]
                        }, 
                        (err, result) => {
                            if (err) reject(err); 
                            else resolve(result);
                        }
                    );
                    stream.end(req.file.buffer);
                });
                avatarUrl = uploadResult.secure_url;
            } catch (uploadError) {
                console.error('Error uploading avatar:', uploadError);
                return res.render('password', { 
                    username, 
                    message: 'حدث خطأ في رفع الصورة، الرجاء المحاولة مرة أخرى' 
                });
            }
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({ 
            username, 
            passwordHash: hashedPassword, 
            avatarUrl,
            lastSeen: new Date()
        });
        
        await user.save();

        req.session.regenerate((err) => {
            if (err) {
                console.error('❌ خطأ في إعادة توليد الجلسة:', err);
                return res.redirect('/login');
            }

            req.session.userId = user._id.toString();
            req.session.username = user.username;
            req.session.avatarUrl = user.avatarUrl;
            req.session.pendingUsername = null;

            console.log('✅ تم إنشاء الجلسة الجديدة:', {
                userId: req.session.userId,
                username: req.session.username
            });

            req.session.save((saveErr) => {
                if (saveErr) {
                    console.error('❌ خطأ في حفظ الجلسة:', saveErr);
                    return res.redirect('/login');
                }
                
                console.log('🔄 التوجيه إلى / بعد التسجيل');
                res.redirect('/');
            });
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).render('password', { 
            username: req.session.pendingUsername, 
            message: 'حدث خطأ أثناء إنشاء الحساب، الرجاء المحاولة مرة أخرى' 
        });
    }
});

// صفحة تسجيل الدخول
app.get('/login', redirectIfLoggedIn, (req, res) => {
    res.render('login', { 
        message: null,
        title: 'تسجيل الدخول'
    });
});

// عملية تسجيل الدخول
app.post('/login', redirectIfLoggedIn, async (req, res) => {
    try {
        console.log('🚀 بدء تسجيل الدخول...');
        const { username, password, rememberMe } = req.body;
        
        console.log('📝 البيانات المستلمة:', { 
            username: username ? username : 'مفقود'
        });
        
        if (!username || !password) {
            return res.render('login', { 
                message: 'الرجاء إدخال اسم المستخدم وكلمة السر',
                title: 'تسجيل الدخول'
            });
        }

        const user = await User.findOne({ 
            username: new RegExp(`^${username.trim()}$`, 'i') 
        });
        
        if (!user) {
            return res.render('login', { 
                message: 'اسم المستخدم أو كلمة السر غير صحيحة',
                title: 'تسجيل الدخول'
            });
        }

        const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordValid) {
            return res.render('login', { 
                message: 'اسم المستخدم أو كلمة السر غير صحيحة',
                title: 'تسجيل الدخول'
            });
        }

        await User.findByIdAndUpdate(user._id, { 
            lastSeen: new Date()
        });

        req.session.regenerate((err) => {
            if (err) {
                console.error('❌ خطأ في إعادة توليد الجلسة:', err);
                return res.render('login', { 
                    message: 'حدث خطأ في تسجيل الدخول',
                    title: 'تسجيل الدخول'
                });
            }

            req.session.userId = user._id.toString();
            req.session.username = user.username;
            req.session.avatarUrl = user.avatarUrl;

            console.log('✅ تم إنشاء الجلسة الجديدة:', {
                userId: req.session.userId,
                username: req.session.username,
                sessionId: req.sessionID
            });

            if (rememberMe) {
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
                console.log('💾 تم تفعيل خاصية تذكرني لمدة 30 يوم');
            }

            req.session.save((saveErr) => {
                if (saveErr) {
                    console.error('❌ خطأ في حفظ الجلسة:', saveErr);
                    return res.render('login', { 
                        message: 'حدث خطأ في تسجيل الدخول',
                        title: 'تسجيل الدخول'
                    });
                }
                
                console.log('💾 تم حفظ الجلسة بنجاح');
                console.log('🔄 التوجيه إلى /');
                res.redirect('/');
            });
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.render('login', { 
            message: 'حدث خطأ أثناء تسجيل الدخول، الرجاء المحاولة مرة أخرى',
            title: 'تسجيل الدخول'
        });
    }
});

// --- Admin Routes ---

// صفحة تسجيل دخول المسؤول
app.get('/admin/login', (req, res) => {
    if (req.session.isAdmin) {
        return res.redirect('/admin');
    }
    
    res.render('admin/login', {
        message: null,
        title: 'تسجيل دخول المسؤول'
    });
});

// عملية تسجيل دخول المسؤول
app.post('/admin/login', async (req, res) => {
    try {
        const { adminPassword } = req.body;
        
        if (!adminPassword) {
            return res.render('admin/login', {
                message: 'الرجاء إدخال كلمة سر المسؤول',
                title: 'تسجيل دخول المسؤول'
            });
        }

        if (adminPassword !== ADMIN_PASSWORD) {
            return res.render('admin/login', {
                message: 'كلمة سر المسؤول غير صحيحة',
                title: 'تسجيل دخول المسؤول'
            });
        }

        if (!req.session.userId) {
            return res.render('admin/login', {
                message: 'يجب تسجيل الدخول كعضو أولاً',
                title: 'تسجيل دخول المسؤول'
            });
        }

        req.session.isAdmin = true;
        req.session.save((err) => {
            if (err) {
                console.error('Error saving admin session:', err);
                return res.render('admin/login', {
                    message: 'حدث خطأ في تسجيل الدخول',
                    title: 'تسجيل دخول المسؤول'
                });
            }
            
            console.log(`✅ تم تسجيل دخول المسؤول: ${req.session.username}`);
            res.redirect('/admin');
        });
        
    } catch (error) {
        console.error('Admin login error:', error);
        res.render('admin/login', {
            message: 'حدث خطأ أثناء تسجيل الدخول',
            title: 'تسجيل دخول المسؤول'
        });
    }
});

// تسجيل خروج المسؤول
app.get('/admin/logout', requireAdmin, (req, res) => {
    req.session.isAdmin = false;
    req.session.save((err) => {
        if (err) {
            console.error('Error saving session after admin logout:', err);
        }
        res.redirect('/');
    });
});

// لوحة تحكم المسؤول
app.get('/admin', requireAdmin, async (req, res) => {
    try {
        const [users, messages, stats] = await Promise.all([
            User.find().select('username avatarUrl lastSeen createdAt isBanned').sort({ createdAt: -1 }).lean(),
            Message.find().populate('userId', 'username').populate('toUserId', 'username').sort({ createdAt: -1 }).limit(50).lean(),
            Promise.all([
                User.countDocuments(),
                Message.countDocuments(),
                Friendship.countDocuments(),
                User.countDocuments({ isBanned: true })
            ])
        ]);

        res.render('admin/dashboard', {
            users,
            messages,
            stats: {
                totalUsers: stats[0],
                totalMessages: stats[1],
                totalFriendships: stats[2],
                bannedUsers: stats[3]
            },
            username: req.session.username,
            avatarUrl: req.session.avatarUrl,
            title: 'لوحة الإدارة'
        });
        
    } catch (error) {
        console.error('Error loading admin dashboard:', error);
        res.status(500).render('error', {
            message: 'حدث خطأ في تحميل لوحة الإدارة',
            title: 'خطأ'
        });
    }
});

// إدارة المستخدمين
app.get('/admin/users', requireAdmin, async (req, res) => {
    try {
        const users = await User.find()
            .select('username avatarUrl lastSeen createdAt isBanned')
            .sort({ createdAt: -1 })
            .lean();

        res.render('admin/users', {
            users,
            username: req.session.username,
            avatarUrl: req.session.avatarUrl,
            userId: req.session.userId,
            title: 'إدارة المستخدمين'
        });
        
    } catch (error) {
        console.error('Error loading admin users:', error);
        res.status(500).render('error', {
            message: 'حدث خطأ في تحميل صفحة المستخدمين',
            title: 'خطأ'
        });
    }
});

// حذف مستخدم
app.post('/admin/users/delete/:id', requireAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        
        // منع حذف المستخدم المسؤول الحالي
        if (userId === req.session.userId) {
            return res.json({ success: false, message: 'لا يمكن حذف حسابك الخاص' });
        }

        await Promise.all([
            User.findByIdAndDelete(userId),
            Message.deleteMany({ 
                $or: [
                    { userId: userId },
                    { toUserId: userId }
                ] 
            }),
            Friendship.deleteMany({
                $or: [
                    { requester: userId },
                    { recipient: userId }
                ]
            })
        ]);

        res.json({ success: true, message: 'تم حذف المستخدم وجميع بياناته بنجاح' });
        
    } catch (error) {
        console.error('Error deleting user:', error);
        res.json({ success: false, message: 'حدث خطأ أثناء حذف المستخدم' });
    }
});

// حظر/فك حظر مستخدم
app.post('/admin/users/ban/:id', requireAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        const { action } = req.body;
        
        // منع حظر المستخدم المسؤول الحالي
        if (userId === req.session.userId) {
            return res.json({ success: false, message: 'لا يمكن حظر حسابك الخاص' });
        }

        const user = await User.findByIdAndUpdate(
            userId, 
            { isBanned: action === 'ban' }, 
            { new: true }
        );

        if (!user) {
            return res.json({ success: false, message: 'المستخدم غير موجود' });
        }

        const message = action === 'ban' ? 'تم حظر المستخدم بنجاح' : 'تم فك حظر المستخدم بنجاح';
        res.json({ success: true, message, isBanned: user.isBanned });
        
    } catch (error) {
        console.error('Error banning user:', error);
        res.json({ success: false, message: 'حدث خطأ أثناء حظر المستخدم' });
    }
});

// إدارة الرسائل
app.get('/admin/messages', requireAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 50, search = '' } = req.query;
        
        let query = {};
        if (search) {
            query = {
                $or: [
                    { text: { $regex: search, $options: 'i' } },
                    { username: { $regex: search, $options: 'i' } }
                ]
            };
        }

        const messages = await Message.find(query)
            .populate('userId', 'username avatarUrl')
            .populate('toUserId', 'username')
            .sort({ createdAt: -1 })
            .limit(parseInt(limit))
            .skip((parseInt(page) - 1) * parseInt(limit))
            .lean();

        const totalMessages = await Message.countDocuments(query);

        res.render('admin/messages', {
            messages,
            username: req.session.username,
            avatarUrl: req.session.avatarUrl,
            userId: req.session.userId,
            title: 'إدارة الرسائل',
            currentPage: parseInt(page),
            totalPages: Math.ceil(totalMessages / parseInt(limit)),
            search
        });
        
    } catch (error) {
        console.error('Error loading admin messages:', error);
        res.status(500).render('error', {
            message: 'حدث خطأ في تحميل الرسائل',
            title: 'خطأ'
        });
    }
});

// حذف رسالة
app.post('/admin/messages/delete/:id', requireAdmin, async (req, res) => {
    try {
        const messageId = req.params.id;
        
        const message = await Message.findByIdAndDelete(messageId);
        
        if (!message) {
            return res.json({ success: false, message: 'الرسالة غير موجودة' });
        }

        res.json({ success: true, message: 'تم حذف الرسالة بنجاح' });
        
    } catch (error) {
        console.error('Error deleting message:', error);
        res.json({ success: false, message: 'حدث خطأ أثناء حذف الرسالة' });
    }
});

// حذف جميع رسائل مستخدم
app.post('/admin/messages/delete-user-messages/:userId', requireAdmin, async (req, res) => {
    try {
        const userId = req.params.userId;
        
        const result = await Message.deleteMany({
            $or: [
                { userId: userId },
                { toUserId: userId }
            ]
        });

        res.json({ 
            success: true, 
            message: `تم حذف ${result.deletedCount} رسالة بنجاح`,
            deletedCount: result.deletedCount
        });
        
    } catch (error) {
        console.error('Error deleting user messages:', error);
        res.json({ success: false, message: 'حدث خطأ أثناء حذف رسائل المستخدم' });
    }
});

// --- باقي المسارات (الملف الأصلي) ---

// التحقق من الجلسة النشطة
app.get('/check-session', (req, res) => {
    const hasActiveSession = !!req.session.userId;
    console.log('🔍 فحص الجلسة:', {
        hasActiveSession,
        userId: req.session.userId,
        username: req.session.username
    });
    
    if (hasActiveSession) {
        res.json({ 
            success: true, 
            message: 'يوجد جلسة نشطة',
            redirect: '/'
        });
    } else {
        res.json({ 
            success: false, 
            message: 'لا يوجد جلسة نشطة'
        });
    }
});

// الحصول على عدد الرسائل غير المقروءة
app.get('/unread-count', requireLogin, async (req, res) => {
    try {
        const unreadCount = await Message.countDocuments({
            toUserId: req.session.userId,
            read: false
        });

        res.json({ success: true, unreadCount });
    } catch (error) {
        console.error('Error getting unread count:', error);
        res.json({ success: false, unreadCount: 0 });
    }
});

// الحصول على عدد الرسائل غير المقروءة لصديق معين
app.get('/unread-count/:friendId', requireLogin, async (req, res) => {
    try {
        const { friendId } = req.params;
        
        console.log(`🔍 جلب عدد الرسائل غير المقروءة من ${friendId} إلى ${req.session.userId}`);
        
        const unreadCount = await Message.countDocuments({
            userId: friendId,
            toUserId: req.session.userId,
            read: false
        });

        console.log(`📊 عدد الرسائل غير المقروءة: ${unreadCount}`);

        res.json({ success: true, unreadCount });
    } catch (error) {
        console.error('Error getting friend unread count:', error);
        res.json({ success: false, unreadCount: 0 });
    }
});

// تحديث حالة الرسائل كمقروءة
app.post('/mark-as-read/:friendId', requireLogin, async (req, res) => {
    try {
        const { friendId } = req.params;
        
        console.log(`📝 تحديث حالة الرسائل كمقروءة من ${friendId} إلى ${req.session.userId}`);
        
        const result = await Message.updateMany({
            userId: friendId,
            toUserId: req.session.userId,
            read: false
        }, {
            $set: { 
                read: true,
                readAt: new Date()
            }
        });

        console.log(`✅ تم تحديث ${result.modifiedCount} رسالة كمقروءة`);

        res.json({ success: true, message: 'تم تحديث حالة الرسائل', updatedCount: result.modifiedCount });
    } catch (error) {
        console.error('Error marking messages as read:', error);
        res.json({ success: false, message: 'حدث خطأ' });
    }
});

// صفحة التصحيح - لفحص الجلسة
app.get('/debug-session', (req, res) => {
    res.json({
        sessionId: req.sessionID,
        userId: req.session.userId,
        username: req.session.username,
        isAdmin: req.session.isAdmin,
        sessionData: req.session,
        cookies: req.headers.cookie
    });
});

// تسجيل الدخول التلقائي
app.post('/auto-login', async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.json({ success: false, message: 'User ID is required' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        await User.findByIdAndUpdate(user._id, { 
            lastSeen: new Date()
        });

        req.session.userId = user._id;
        req.session.username = user.username;
        req.session.avatarUrl = user.avatarUrl;

        res.json({ 
            success: true, 
            username: user.username,
            message: 'Auto-login successful'
        });
        
    } catch (error) {
        console.error('Auto-login error:', error);
        res.json({ 
            success: false, 
            message: 'Auto-login failed' 
        });
    }
});

// تسجيل الخروج
app.get('/logout', requireLogin, (req, res) => {
    const userId = req.session.userId;
    const username = req.session.username;
    
    console.log('🚪 تسجيل الخروج:', { userId, username });
    
    if (userId) {
        User.findByIdAndUpdate(userId, { 
            lastSeen: new Date()
        }).catch(err => console.error('Error updating last seen:', err));
    }
    
    req.session.destroy((err) => {
        if (err) {
            console.error('❌ خطأ في تدمير الجلسة:', err);
            return res.status(500).send('خطأ في تسجيل الخروج');
        }
        
        console.log('✅ تم تسجيل الخروج بنجاح');
        res.redirect('/login');
    });
});

// --- Profile Routes ---
app.get('/profile', requireLogin, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.redirect('/logout');
        }

        const [friendsCount, messagesCount] = await Promise.all([
            Friendship.countDocuments({
                $or: [
                    { requester: req.session.userId, status: 'accepted' },
                    { recipient: req.session.userId, status: 'accepted' }
                ]
            }),
            Message.countDocuments({
                $or: [
                    { userId: req.session.userId },
                    { toUserId: req.session.userId }
                ]
            })
        ]);

        res.render('profile', {
            user: {
                _id: user._id,
                username: user.username,
                avatarUrl: user.avatarUrl,
                createdAt: user.createdAt
            },
            username: req.session.username,
            avatarUrl: req.session.avatarUrl,
            message: null,
            success: null,
            passwordError: null,
            stats: {
                friendsCount,
                messagesCount
            }
        });
        
    } catch (error) {
        console.error('Error loading profile:', error);
        res.status(500).render('error', { 
            message: 'حدث خطأ في تحميل البروفايل',
            title: 'خطأ'
        });
    }
});

// --- Profile Update Routes ---
app.post('/update-profile', requireLogin, upload.single('avatar'), async (req, res) => {
    try {
        const { username } = req.body;
        const user = await User.findById(req.session.userId);
        
        if (!user) {
            return res.redirect('/logout');
        }

        let message = null;
        let success = null;

        if (username && username !== user.username) {
            const trimmedUsername = username.trim();
            
            if (trimmedUsername.length < 3) {
                message = 'اسم المستخدم يجب أن يكون 3 أحرف على الأقل';
            } else {
                const existingUser = await User.findOne({ 
                    username: new RegExp(`^${trimmedUsername}$`, 'i'),
                    _id: { $ne: user._id }
                });
                
                if (existingUser) {
                    message = 'اسم المستخدم مستخدم بالفعل';
                } else {
                    user.username = trimmedUsername;
                    req.session.username = trimmedUsername;
                    success = 'تم تحديث البروفايل بنجاح';
                }
            }
        }

        if (req.file && !message) {
            try {
                console.log('🖼️ رفع صورة جديدة...');
                const uploadResult = await new Promise((resolve, reject) => {
                    const stream = cloudinary.uploader.upload_stream(
                        { 
                            folder: 'chat-app/avatars',
                            transformation: [
                                { width: 200, height: 200, crop: 'fill' },
                                { quality: 'auto' },
                                { format: 'webp' }
                            ]
                        }, 
                        (err, result) => {
                            if (err) reject(err); 
                            else resolve(result);
                        }
                    );
                    stream.end(req.file.buffer);
                });
                
                user.avatarUrl = uploadResult.secure_url;
                req.session.avatarUrl = uploadResult.secure_url;
                success = success || 'تم تحديث البروفايل بنجاح';
                console.log('✅ تم رفع الصورة:', uploadResult.secure_url);
                
            } catch (uploadError) {
                console.error('❌ خطأ في رفع الصورة:', uploadError);
                message = message || 'حدث خطأ في رفع الصورة';
            }
        }

        if (!message) {
            await user.save();
            console.log('✅ تم تحديث بيانات المستخدم:', user.username);
        }

        const [friendsCount, messagesCount] = await Promise.all([
            Friendship.countDocuments({
                $or: [
                    { requester: req.session.userId, status: 'accepted' },
                    { recipient: req.session.userId, status: 'accepted' }
                ]
            }),
            Message.countDocuments({
                $or: [
                    { userId: req.session.userId },
                    { toUserId: req.session.userId }
                ]
            })
        ]);

        res.render('profile', {
            user: {
                _id: user._id,
                username: user.username,
                avatarUrl: user.avatarUrl,
                createdAt: user.createdAt
            },
            username: req.session.username,
            avatarUrl: req.session.avatarUrl,
            message: message,
            success: success,
            passwordError: null,
            stats: {
                friendsCount,
                messagesCount
            }
        });
        
    } catch (error) {
        console.error('❌ خطأ في تحديث البروفايل:', error);
        res.status(500).render('error', { 
            message: 'حدث خطأ في تحديث البروفايل',
            title: 'خطأ'
        });
    }
});

// تحديث كلمة السر
app.post('/update-password', requireLogin, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(req.session.userId);
        
        if (!user) {
            return res.redirect('/logout');
        }

        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.passwordHash);
        if (!isCurrentPasswordValid) {
            const [friendsCount, messagesCount] = await Promise.all([
                Friendship.countDocuments({
                    $or: [
                        { requester: req.session.userId, status: 'accepted' },
                        { recipient: req.session.userId, status: 'accepted' }
                    ]
                }),
                Message.countDocuments({
                    $or: [
                        { userId: req.session.userId },
                        { toUserId: req.session.userId }
                    ]
                })
            ]);

            return res.render('profile', {
                user: {
                    _id: user._id,
                    username: user.username,
                    avatarUrl: user.avatarUrl,
                    createdAt: user.createdAt
                },
                username: req.session.username,
                avatarUrl: req.session.avatarUrl,
                message: null,
                success: null,
                passwordError: 'كلمة السر الحالية غير صحيحة',
                stats: {
                    friendsCount,
                    messagesCount
                }
            });
        }

        if (!newPassword || newPassword.length < 4) {
            const [friendsCount, messagesCount] = await Promise.all([
                Friendship.countDocuments({
                    $or: [
                        { requester: req.session.userId, status: 'accepted' },
                        { recipient: req.session.userId, status: 'accepted' }
                    ]
                }),
                Message.countDocuments({
                    $or: [
                        { userId: req.session.userId },
                        { toUserId: req.session.userId }
                    ]
                })
            ]);

            return res.render('profile', {
                user: {
                    _id: user._id,
                    username: user.username,
                    avatarUrl: user.avatarUrl,
                    createdAt: user.createdAt
                },
                username: req.session.username,
                avatarUrl: req.session.avatarUrl,
                message: null,
                success: null,
                passwordError: 'كلمة السر الجديدة يجب أن تكون 4 أحرف على الأقل',
                stats: {
                    friendsCount,
                    messagesCount
                }
            });
        }

        user.passwordHash = await bcrypt.hash(newPassword, 12);
        await user.save();

        console.log('✅ تم تحديث كلمة السر للمستخدم:', user.username);

        const [friendsCount, messagesCount] = await Promise.all([
            Friendship.countDocuments({
                $or: [
                    { requester: req.session.userId, status: 'accepted' },
                    { recipient: req.session.userId, status: 'accepted' }
                ]
            }),
            Message.countDocuments({
                $or: [
                    { userId: req.session.userId },
                    { toUserId: req.session.userId }
                ]
            })
        ]);

        res.render('profile', {
            user: {
                _id: user._id,
                username: user.username,
                avatarUrl: user.avatarUrl,
                createdAt: user.createdAt
            },
            username: req.session.username,
            avatarUrl: req.session.avatarUrl,
            message: null,
            success: 'تم تحديث كلمة السر بنجاح',
            passwordError: null,
            stats: {
                friendsCount,
                messagesCount
            }
        });
        
    } catch (error) {
        console.error('❌ خطأ في تحديث كلمة السر:', error);
        res.status(500).render('error', { 
            message: 'حدث خطأ في تحديث كلمة السر',
            title: 'خطأ'
        });
    }
});

// --- Chat Routes ---
app.get('/chat', requireLogin, async (req, res) => {
    try {
        console.log('💬 تحميل الشات العام');
        
        if (!req.session.userId) {
            console.log('❌ الجلسة غير موجودة في /chat، التوجيه إلى /login');
            return res.redirect('/login');
        }

        const messages = await Message.find({ toUserId: null })
            .populate('userId', 'username avatarUrl')
            .sort({ createdAt: 1 })
            .limit(100)
            .lean();

        console.log('✅ تم تحميل الرسائل:', messages.length);

        res.render('chat', {
            username: req.session.username,
            avatarUrl: req.session.avatarUrl,
            messages: messages.map(msg => ({
                ...msg,
                username: msg.userId.username,
                avatarUrl: msg.userId.avatarUrl,
                userId: msg.userId._id.toString()
            })),
            userId: req.session.userId.toString(),
            title: 'الشات العام'
        });
        
    } catch (error) {
        console.error('Error loading chat:', error);
        res.status(500).render('error', { 
            message: 'حدث خطأ في تحميل الشات',
            title: 'خطأ'
        });
    }
});

// --- Friends Routes ---

// عرض جميع المستخدمين
app.get('/users', requireLogin, async (req, res) => {
    try {
        const users = await User.find({ _id: { $ne: req.session.userId } })
            .select('username avatarUrl lastSeen')
            .sort({ username: 1 })
            .lean();

        const [sentRequests, receivedRequests, friends] = await Promise.all([
            Friendship.find({ requester: req.session.userId }).lean(),
            Friendship.find({ recipient: req.session.userId }).lean(),
            Friendship.find({
                $or: [
                    { requester: req.session.userId, status: 'accepted' },
                    { recipient: req.session.userId, status: 'accepted' }
                ]
            }).lean()
        ]);

        const sentIds = sentRequests.map(r => r.recipient.toString());
        const receivedIds = receivedRequests.map(r => r.requester.toString());
        const friendIds = friends.map(f => {
            return f.requester.toString() === req.session.userId.toString() ? 
                f.recipient.toString() : f.requester.toString();
        });

        res.render('users', { 
            users, 
            sentIds, 
            receivedIds, 
            friendIds,
            username: req.session.username,
            avatarUrl: req.session.avatarUrl,
            title: 'المستخدمون'
        });
        
    } catch (error) {
        console.error('Error loading users:', error);
        res.status(500).render('error', { 
            message: 'حدث خطأ في تحميل المستخدمين',
            title: 'خطأ'
        });
    }
});

// إرسال طلب صداقة
app.post('/friend-request/:id', requireLogin, async (req, res) => {
    try {
        const recipientId = req.params.id;

        if (recipientId === req.session.userId.toString()) {
            return res.status(400).json({ error: 'لا يمكن إرسال طلب صداقة لنفسك' });
        }

        const existingFriendship = await Friendship.findOne({
            $or: [
                { requester: req.session.userId, recipient: recipientId },
                { requester: recipientId, recipient: req.session.userId }
            ]
        });

        if (existingFriendship) {
            return res.status(400).json({ 
                error: 'تم إرسال طلب مسبقاً أو أنكم أصدقاء بالفعل' 
            });
        }

        const friendship = new Friendship({ 
            requester: req.session.userId, 
            recipient: recipientId 
        });
        await friendship.save();

        res.json({ success: true, message: 'تم إرسال طلب الصداقة بنجاح' });
        
    } catch (error) {
        console.error('Error sending friend request:', error);
        res.status(500).json({ error: 'حدث خطأ في إرسال طلب الصداقة' });
    }
});

// عرض طلبات الصداقة
app.get('/friend-requests', requireLogin, async (req, res) => {
    try {
        const requests = await Friendship.find({ 
            recipient: req.session.userId, 
            status: 'pending' 
        })
        .populate('requester', 'username avatarUrl createdAt')
        .sort({ createdAt: -1 })
        .lean();

        res.render('friend-requests', { 
            requests,
            username: req.session.username,
            avatarUrl: req.session.avatarUrl,
            title: 'طلبات الصداقة'
        });
        
    } catch (error) {
        console.error('Error loading friend requests:', error);
        res.status(500).render('error', { 
            message: 'حدث خطأ في تحميل طلبات الصداقة',
            title: 'خطأ'
        });
    }
});

// قبول طلب صداقة
app.post('/friend-accept/:id', requireLogin, async (req, res) => {
    try {
        const requesterId = req.params.id;
        const friendship = await Friendship.findOne({ 
            requester: requesterId, 
            recipient: req.session.userId,
            status: 'pending'
        });
        
        if (!friendship) {
            return res.status(404).json({ error: 'الطلب غير موجود' });
        }
        
        friendship.status = 'accepted';
        await friendship.save();

        res.redirect('/friend-requests');
        
    } catch (error) {
        console.error('Error accepting friend request:', error);
        res.status(500).json({ error: 'حدث خطأ في قبول طلب الصداقة' });
    }
});

// رفض طلب صداقة
app.get('/friend-reject/:id', requireLogin, async (req, res) => {
    try {
        const requesterId = req.params.id;
        const result = await Friendship.findOneAndDelete({ 
            requester: requesterId, 
            recipient: req.session.userId 
        });

        if (!result) {
            return res.status(404).json({ error: 'الطلب غير موجود' });
        }

        res.redirect('/friend-requests');
        
    } catch (error) {
        console.error('Error rejecting friend request:', error);
        res.status(500).json({ error: 'حدث خطأ في رفض طلب الصداقة' });
    }
});

// إلغاء طلب صداقة
app.post('/friend-cancel/:id', requireLogin, async (req, res) => {
    try {
        const recipientId = req.params.id;
        const result = await Friendship.findOneAndDelete({ 
            requester: req.session.userId, 
            recipient: recipientId 
        });

        if (!result) {
            return res.status(404).json({ error: 'الطلب غير موجود' });
        }

        res.json({ success: true, message: 'تم إلغاء طلب الصداقة' });
        
    } catch (error) {
        console.error('Error canceling friend request:', error);
        res.status(500).json({ error: 'حدث خطأ في إلغاء طلب الصداقة' });
    }
});

// الدردشة الخاصة
app.get('/chat-private/:id', requireLogin, async (req, res) => {
    try {
        const friendId = req.params.id;
        
        const friendship = await Friendship.findOne({
            $or: [
                { requester: req.session.userId, recipient: friendId, status: 'accepted' },
                { requester: friendId, recipient: req.session.userId, status: 'accepted' }
            ]
        }).populate('requester recipient');

        if (!friendship) {
            return res.status(403).render('error', { 
                message: 'لا يمكنك الدردشة مع هذا المستخدم',
                title: 'خطأ في الصلاحيات'
            });
        }

        await Message.updateMany({
            userId: friendId,
            toUserId: req.session.userId,
            read: false
        }, {
            $set: { 
                read: true,
                readAt: new Date()
            }
        });

        const messages = await Message.find({
            $or: [
                { userId: req.session.userId, toUserId: friendId },
                { userId: friendId, toUserId: req.session.userId }
            ]
        })
        .populate('userId', 'username avatarUrl')
        .sort({ createdAt: 1 })
        .limit(100)
        .lean();

        const friend = friendship.requester._id.toString() === friendId ? 
            friendship.requester : friendship.recipient;

        res.render('chat-private', {
            messages: messages.map(msg => ({
                ...msg,
                username: msg.userId.username,
                avatarUrl: msg.userId.avatarUrl,
                userId: msg.userId._id.toString()
            })),
            friendId,
            friendUsername: friend.username,
            friendAvatar: friend.avatarUrl,
            userId: req.session.userId.toString(),
            username: req.session.username,
            avatarUrl: req.session.avatarUrl || '/default-avatar.png',
            title: `الدردشة مع ${friend.username}`
        });
        
    } catch (error) {
        console.error('Error loading private chat:', error);
        res.status(500).render('error', { 
            message: 'حدث خطأ في تحميل المحادثة',
            title: 'خطأ'
        });
    }
});

// --- Socket.IO Setup ---
const io = require('socket.io')(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

io.use((socket, next) => {
    sessionMiddleware(socket.request, {}, next);
});

io.on('connection', async (socket) => {
    const session = socket.request.session;
    
    if (!session.userId) {
        console.log('❌ اتصال غير مصرح به - قطع الاتصال');
        socket.disconnect();
        return;
    }

    console.log(`✅ اتصال جديد: ${session.username} (${session.userId}) - Socket: ${socket.id}`);

    socket.join(session.userId.toString());

    try {
        await User.findByIdAndUpdate(session.userId, { 
            lastSeen: new Date()
        });
    } catch (error) {
        console.error('Error updating user last seen:', error);
    }

    socket.on('chat message', async (data) => {
        try {
            if (!data.text || data.text.trim() === '') {
                return;
            }

            const user = await User.findById(session.userId);
            if (!user) {
                console.log('User not found for socket message');
                return;
            }

            const messageData = {
                userId: session.userId,
                username: user.username,
                avatarUrl: user.avatarUrl,
                text: data.text.trim(),
                toUserId: null,
                read: true
            };

            const message = new Message(messageData);
            await message.save();

            console.log(`📢 رسالة عامة من ${user.username}: ${data.text.trim()}`);

            io.emit('chat message', {
                ...messageData,
                _id: message._id,
                createdAt: message.createdAt
            });

        } catch (error) {
            console.error('Error handling chat message:', error);
            socket.emit('error', { message: 'Failed to send message' });
        }
    });

    socket.on('private message', async (data) => {
        try {
            if (!data.text || data.text.trim() === '' || !data.toUserId) {
                return;
            }

            const user = await User.findById(session.userId);
            if (!user) {
                console.log('User not found for private message');
                return;
            }

            const messageData = {
                userId: session.userId,
                username: user.username,
                avatarUrl: user.avatarUrl,
                text: data.text.trim(),
                toUserId: data.toUserId,
                read: false
            };

            const message = new Message(messageData);
            await message.save();

            console.log(`🔒 رسالة خاصة من ${user.username} إلى ${data.toUserId}: ${data.text.trim()}`);

            const unreadCount = await Message.countDocuments({
                userId: session.userId,
                toUserId: data.toUserId,
                read: false
            });

            console.log(`📊 عدد الرسائل غير المقروءة من ${user.username} إلى ${data.toUserId}: ${unreadCount}`);

            const messageToSend = {
                ...messageData,
                _id: message._id,
                createdAt: message.createdAt
            };

            socket.emit('private message', messageToSend);
            
            socket.to(data.toUserId).emit('private message', messageToSend);
            
            socket.to(data.toUserId).emit('new message notification', {
                from: user.username,
                fromId: session.userId,
                unreadCount: unreadCount
            });

            console.log(`📨 تم إرسال إشعار إلى ${data.toUserId} بعدد الرسائل غير المقروءة: ${unreadCount}`);

        } catch (error) {
            console.error('Error handling private message:', error);
            socket.emit('error', { message: 'Failed to send private message' });
        }
    });

    socket.on('mark as read', async (data) => {
        try {
            const { friendId } = data;
            
            await Message.updateMany({
                userId: friendId,
                toUserId: session.userId,
                read: false
            }, {
                $set: { 
                    read: true,
                    readAt: new Date()
                }
            });

            socket.to(friendId).emit('messages read', {
                readerId: session.userId,
                readerName: session.username
            });

        } catch (error) {
            console.error('Error marking messages as read:', error);
        }
    });

    socket.on('typing', (data) => {
        if (data.toUserId) {
            socket.to(data.toUserId).emit('typing', {
                userId: session.userId,
                username: session.username,
                isTyping: data.isTyping
            });
        }
    });

    socket.on('disconnect', async () => {
        console.log(`❌ انقطع الاتصال: ${session.username} - Socket: ${socket.id}`);
        
        try {
            await User.findByIdAndUpdate(session.userId, { 
                lastSeen: new Date()
            });
        } catch (error) {
            console.error('Error updating last seen on disconnect:', error);
        }
    });

    socket.on('error', (error) => {
        console.error('Socket error:', error);
    });
});

// --- Error Handling ---
app.use((req, res) => {
    res.status(404).render('error', {
        message: 'الصفحة المطلوبة غير موجودة',
        title: '404 - الصفحة غير موجودة'
    });
});

app.use((error, req, res, next) => {
    console.error('❌ معالج الأخطاء العام:', error);
    res.status(500).render('error', {
        message: 'حدث خطأ غير متوقع في الخادم',
        title: 'خطأ في الخادم'
    });
});

// --- Server Startup ---
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log(`🚀 الخادم يعمل على http://localhost:${PORT}`);
    console.log(`📱 البيئة: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🗄️  قاعدة البيانات: ${process.env.MONGODB_URI || 'mongodb://localhost:27017/chat-app'}`);
    console.log(`🔐 كلمة سر المسؤول: ${ADMIN_PASSWORD}`);
});

process.on('SIGTERM', () => {
    console.log('🛑 استقبال SIGTERM، إغلاق الخادم بشكل أنيق');
    server.close(() => {
        console.log('✅ تم إغلاق الخادم');
        mongoose.connection.close();
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('🛑 استقبال SIGINT، إغلاق الخادم بشكل أنيق');
    server.close(() => {
        console.log('✅ تم إغلاق الخادم');
        mongoose.connection.close();
        process.exit(0);
    });
});

module.exports = app;
