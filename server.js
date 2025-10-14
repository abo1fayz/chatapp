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
        secure: false, // ضع true في production
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
        
        if (!username) {
            console.log('❌ لا يوجد اسم مستخدم في الجلسة');
            return res.redirect('/');
        }

        const { password } = req.body;
        
        // التحقق من كلمة السر
        if (!password || password.length < 4) {
            return res.render('password', { 
                username, 
                message: 'كلمة السر يجب أن تكون 4 أحرف على الأقل' 
            });
        }

        let avatarUrl = null;
        
        // رفع الصورة إذا وجدت
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

        // إنشاء المستخدم
        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({ 
            username, 
            passwordHash: hashedPassword, 
            avatarUrl,
            lastSeen: new Date()
        });
        
        await user.save();

        // 🔥 تسجيل الدخول التلقائي - الإصلاح هنا
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

            // حفظ الجلسة قبل التوجيه
            req.session.save((saveErr) => {
                if (saveErr) {
                    console.error('❌ خطأ في حفظ الجلسة:', saveErr);
                    return res.redirect('/login');
                }
                
                console.log('🔄 التوجيه إلى /chat بعد التسجيل');
                res.redirect('/chat');
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

// عملية تسجيل الدخول - الإصلاح الكامل
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

        // تحديث آخر وقت ظهور
        await User.findByIdAndUpdate(user._id, { 
            lastSeen: new Date()
        });

        // 🔥 الإصلاح: استخدام regenerate لإنشاء جلسة جديدة
        req.session.regenerate((err) => {
            if (err) {
                console.error('❌ خطأ في إعادة توليد الجلسة:', err);
                return res.render('login', { 
                    message: 'حدث خطأ في تسجيل الدخول',
                    title: 'تسجيل الدخول'
                });
            }

            // تعيين بيانات الجلسة الجديدة
            req.session.userId = user._id.toString();
            req.session.username = user.username;
            req.session.avatarUrl = user.avatarUrl;

            console.log('✅ تم إنشاء الجلسة الجديدة:', {
                userId: req.session.userId,
                username: req.session.username,
                sessionId: req.sessionID
            });

            // حفظ تفضيلات تسجيل الدخول
            if (rememberMe) {
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 يوم
                console.log('💾 تم تفعيل خاصية تذكرني لمدة 30 يوم');
            }

            // 🔥 حفظ الجلسة قبل التوجيه
            req.session.save((saveErr) => {
                if (saveErr) {
                    console.error('❌ خطأ في حفظ الجلسة:', saveErr);
                    return res.render('login', { 
                        message: 'حدث خطأ في تسجيل الدخول',
                        title: 'تسجيل الدخول'
                    });
                }
                
                console.log('💾 تم حفظ الجلسة بنجاح');
                console.log('🔄 التوجيه إلى /chat');
                res.redirect('/chat');
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

// صفحة التصحيح - لفحص الجلسة
app.get('/debug-session', (req, res) => {
    res.json({
        sessionId: req.sessionID,
        userId: req.session.userId,
        username: req.session.username,
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

        // تحديث آخر وقت ظهور
        await User.findByIdAndUpdate(user._id, { 
            lastSeen: new Date()
        });

        // إنشاء الجلسة
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
    
    // تحديث آخر وقت ظهور
    if (userId) {
        User.findByIdAndUpdate(userId, { 
            lastSeen: new Date()
        }).catch(err => console.error('Error updating last seen:', err));
    }
    
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
// --- Profile Update Routes ---

// تحديث البروفايل
app.post('/update-profile', requireLogin, upload.single('avatar'), async (req, res) => {
    try {
        const { username } = req.body;
        const user = await User.findById(req.session.userId);
        
        if (!user) {
            return res.redirect('/logout');
        }

        let message = null;
        let success = null;

        // التحقق من اسم المستخدم
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

        // تحديث الصورة
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

        // حفظ التغييرات
        if (!message) {
            await user.save();
            console.log('✅ تم تحديث بيانات المستخدم:', user.username);
        }

        // جلب الإحصائيات المحدثة
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

        // التحقق من كلمة السر الحالية
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

        // التحقق من كلمة السر الجديدة
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

        // تحديث كلمة السر
        user.passwordHash = await bcrypt.hash(newPassword, 12);
        await user.save();

        console.log('✅ تم تحديث كلمة السر للمستخدم:', user.username);

        // جلب الإحصائيات المحدثة
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
        console.log('💬 تحميل الشات للمستخدم:', req.session.username);
        
        // التحقق مرة أخرى من وجود الجلسة
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

// عرض الأصدقاء
app.get('/friends', requireLogin, async (req, res) => {
    try {
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

        const friendList = friends.map(f => {
            if (f.requester._id.toString() === req.session.userId.toString()) {
                return {
                    _id: f.recipient._id,
                    username: f.recipient.username,
                    avatarUrl: f.recipient.avatarUrl,
                    lastSeen: f.recipient.lastSeen
                };
            } else {
                return {
                    _id: f.requester._id,
                    username: f.requester.username,
                    avatarUrl: f.requester.avatarUrl,
                    lastSeen: f.requester.lastSeen
                };
            }
        });

        res.render('friends', { 
            friends: friendList,
            username: req.session.username,
            avatarUrl: req.session.avatarUrl,
            userId: req.session.userId,
            title: 'الأصدقاء'
        });
        
    } catch (error) {
        console.error('Error loading friends:', error);
        res.status(500).render('error', { 
            message: 'حدث خطأ في تحميل قائمة الأصدقاء',
            title: 'خطأ'
        });
    }
});

// الدردشة الخاصة
app.get('/chat-private/:id', requireLogin, async (req, res) => {
    try {
        const friendId = req.params.id;
        
        // التحقق من وجود صداقة
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

        // جلب الرسائل
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

    // استقبال الرسائل الخاصة
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
                toUserId: data.toUserId
            };

            const message = new Message(messageData);
            await message.save();

            console.log(`🔒 رسالة خاصة من ${user.username} إلى ${data.toUserId}: ${data.text.trim()}`);

            // إرسال الرسالة للمستخدم المرسل والمستقبل فقط
            const messageToSend = {
                ...messageData,
                _id: message._id,
                createdAt: message.createdAt
            };

            socket.emit('private message', messageToSend);
            socket.to(data.toUserId).emit('private message', messageToSend);

        } catch (error) {
            console.error('Error handling private message:', error);
            socket.emit('error', { message: 'Failed to send private message' });
        }
    });

    // تحديث حالة الكتابة
    socket.on('typing', (data) => {
        if (data.toUserId) {
            socket.to(data.toUserId).emit('typing', {
                userId: session.userId,
                username: session.username,
                isTyping: data.isTyping
            });
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

    // معالجة الأخطاء
    socket.on('error', (error) => {
        console.error('Socket error:', error);
    });
});

// --- Error Handling ---

// صفحة 404
app.use((req, res) => {
    res.status(404).render('error', {
        message: 'الصفحة المطلوبة غير موجودة',
        title: '404 - الصفحة غير موجودة'
    });
});

// معالج الأخطاء العام
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