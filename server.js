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
    resave: true, // تغيير إلى true
    saveUninitialized: true, // تغيير إلى true
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/chat-app',
        ttl: 14 * 24 * 60 * 60 // 14 يوم
    }),
    cookie: { 
        maxAge: 14 * 24 * 60 * 60 * 1000, // 14 يوم
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production'
    }
});
app.use(sessionMiddleware);

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
        console.log('✅ يوجد جلسة نشطة، التوجيه إلى /chat');
        return res.redirect('/chat');
    }
    next();
}

// --- Routes ---

// الصفحة الرئيسية
app.get('/', redirectIfLoggedIn, (req, res) => {
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
        return res.redirect('/');
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
        console.log('📝 اسم المستخدم:', username);
        
        if (!username) {
            console.log('❌ لا يوجد اسم مستخدم في الجلسة');
            return res.redirect('/');
        }

        const { password } = req.body;
        console.log('🔐 كلمة السر:', password ? 'موجودة' : 'مفقودة');
        
        // التحقق من كلمة السر
        if (!password || password.length < 4) {
            console.log('❌ كلمة السر غير صالحة');
            return res.render('password', { 
                username, 
                message: 'كلمة السر يجب أن تكون 4 أحرف على الأقل' 
            });
        }

        let avatarUrl = null;
        
        // رفع الصورة إذا وجدت
        if (req.file) {
            try {
                console.log('🖼️ رفع الصورة...');
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
                console.log('✅ تم رفع الصورة:', avatarUrl);
            } catch (uploadError) {
                console.error('❌ خطأ في رفع الصورة:', uploadError);
                return res.render('password', { 
                    username, 
                    message: 'حدث خطأ في رفع الصورة، الرجاء المحاولة مرة أخرى' 
                });
            }
        }

        // إنشاء المستخدم
        console.log('👤 جارٍ إنشاء المستخدم...');
        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({ 
            username, 
            passwordHash: hashedPassword, 
            avatarUrl,
            lastSeen: new Date()
        });
        
        await user.save();
        console.log('✅ تم إنشاء المستخدم:', user._id);

        // تسجيل الدخول التلقائي
        req.session.userId = user._id;
        req.session.username = user.username;
        req.session.avatarUrl = user.avatarUrl;
        req.session.pendingUsername = null;

        console.log('✅ تم إنشاء الجلسة:', {
            userId: req.session.userId,
            username: req.session.username
        });

        console.log('🔄 التوجيه إلى /chat');
        res.redirect('/chat');
        
    } catch (error) {
        console.error('❌ خطأ في التسجيل:', error);
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
            username: username ? 'موجود' : 'مفقود', 
            password: password ? 'موجود' : 'مفقود',
            rememberMe: !!rememberMe 
        });
        
        if (!username || !password) {
            console.log('❌ بيانات ناقصة');
            return res.render('login', { 
                message: 'الرجاء إدخال اسم المستخدم وكلمة السر',
                title: 'تسجيل الدخول'
            });
        }

        const user = await User.findOne({ 
            username: new RegExp(`^${username.trim()}$`, 'i') 
        });
        
        console.log('👤 المستخدم الموجود:', user ? `موجود (${user.username})` : 'غير موجود');
        
        if (!user) {
            console.log('❌ مستخدم غير موجود');
            return res.render('login', { 
                message: 'اسم المستخدم أو كلمة السر غير صحيحة',
                title: 'تسجيل الدخول'
            });
        }

        const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
        console.log('🔐 كلمة السر:', isPasswordValid ? 'صحيحة' : 'خاطئة');
        
        if (!isPasswordValid) {
            console.log('❌ كلمة السر خاطئة');
            return res.render('login', { 
                message: 'اسم المستخدم أو كلمة السر غير صحيحة',
                title: 'تسجيل الدخول'
            });
        }

        // تحديث آخر وقت ظهور
        await User.findByIdAndUpdate(user._id, { 
            lastSeen: new Date()
        });

        // إنشاء الجلسة
        req.session.userId = user._id;
        req.session.username = user.username;
        req.session.avatarUrl = user.avatarUrl;

        console.log('✅ تم إنشاء الجلسة:', {
            userId: req.session.userId,
            username: req.session.username,
            sessionID: req.sessionID
        });

        // حفظ تفضيلات تسجيل الدخول في الجلسة
        if (rememberMe) {
            req.session.rememberMe = true;
            req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 يوم
            console.log('💾 تم تفعيل خاصية تذكرني لمدة 30 يوم');
        }

        console.log('🔄 التوجيه إلى /chat');
        res.redirect('/chat');
        
    } catch (error) {
        console.error('❌ خطأ في تسجيل الدخول:', error);
        res.render('login', { 
            message: 'حدث خطأ أثناء تسجيل الدخول، الرجاء المحاولة مرة أخرى',
            title: 'تسجيل الدخول'
        });
    }
});

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
            redirect: '/chat'
        });
    } else {
        res.json({ 
            success: false, 
            message: 'لا يوجد جلسة نشطة'
        });
    }
});

// تسجيل الدخول التلقائي
app.post('/auto-login', async (req, res) => {
    try {
        const { userId } = req.body;
        
        console.log('🔐 محاولة تسجيل دخول تلقائي:', userId);
        
        if (!userId) {
            return res.json({ success: false, message: 'User ID is required' });
        }

        const user = await User.findById(userId);
        if (!user) {
            console.log('❌ مستخدم غير موجود للتسجيل التلقائي');
            return res.json({ success: false, message: 'User not found' });
        }

        // تحديث آخر وقت ظهور
        await User.findByIdAndUpdate(user._id, { 
            lastSeen: new Date()
        });

        // إنشاء الجلسة
        req.session.userId = user._id;
        req.session.username = user.username;
        req.session.avatarUrl = user.avatarUrl;

        console.log('✅ تسجيل دخول تلقائي ناجح:', user.username);

        res.json({ 
            success: true, 
            username: user.username,
            message: 'Auto-login successful'
        });
        
    } catch (error) {
        console.error('❌ خطأ في التسجيل التلقائي:', error);
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
    
    // تحديث آخر وقت ظهور
    if (userId) {
        User.findByIdAndUpdate(userId, { 
            lastSeen: new Date()
        }).catch(err => console.error('Error updating last seen:', err));
    }
    
    // مسح البيانات المحفوظة
    res.clearCookie('rememberMe');
    res.clearCookie('userId');
    res.clearCookie('connect.sid');
    
    // تدمير الجلسة
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

// --- Chat Routes ---
app.get('/chat', requireLogin, async (req, res) => {
    try {
        console.log('💬 تحميل الشات للمستخدم:', req.session.username);
        
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
        console.error('❌ خطأ في تحميل الشات:', error);
        res.status(500).render('error', { 
            message: 'حدث خطأ في تحميل الشات',
            title: 'خطأ'
        });
    }
});

// --- Friends Routes ---
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

// --- Socket.IO Setup ---
const io = require('socket.io')(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// استخدام session middleware مع Socket.IO
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

    // انضمام إلى غرفة المستخدم
    socket.join(session.userId.toString());

    // تحديث حالة الاتصال
    try {
        await User.findByIdAndUpdate(session.userId, { 
            lastSeen: new Date()
        });
    } catch (error) {
        console.error('Error updating user last seen:', error);
    }

    // استقبال رسائل الشات العام
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
                toUserId: null
            };

            const message = new Message(messageData);
            await message.save();

            console.log(`📢 رسالة عامة من ${user.username}: ${data.text.trim()}`);

            // بث الرسالة لجميع المستخدمين المتصلين
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

    // عند انقطاع الاتصال
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
});

// معالجة إغلاق الخادم بشكل أنيق
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