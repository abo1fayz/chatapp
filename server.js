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

// --- MongoDB ---
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// --- Session ---
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'secret123',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  cookie: { 
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 أيام
    httpOnly: true
  }
});
app.use(sessionMiddleware);

// --- EJS ---
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- Static ---
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- Cloudinary ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// --- Multer ---
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  }
});

// --- Middleware ---
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

// --- Routes ---

// الصفحة الرئيسية
app.get('/', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/chat');
  }
  res.render('index', { message: null });
});

// التحقق من اسم المستخدم
app.post('/check-username', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.render('index', { message: 'الرجاء إدخال اسم مستخدم' });
  const exists = await User.findOne({ username: username.trim() });
  if (exists) return res.render('index', { message: 'الاسم مستخدم بالفعل' });
  req.session.pendingUsername = username.trim();
  res.redirect('/set-password');
});

// صفحة كلمة السر وصورة البروفايل
app.get('/set-password', (req, res) => {
  if (!req.session.pendingUsername) return res.redirect('/');
  res.render('password', { username: req.session.pendingUsername, message: null });
});

// التسجيل
app.post('/register', upload.single('avatar'), async (req, res) => {
  try {
    const username = req.session.pendingUsername;
    if (!username) return res.redirect('/');
    const { password } = req.body;
    if (!password || password.length < 4) return res.render('password', { username, message: 'كلمة السر قصيرة' });

    let avatarUrl = null;
    if (req.file) {
      const uploadResult = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream({ folder: 'chat-avatars' }, (err, result) => {
          if (err) reject(err); else resolve(result);
        });
        stream.end(req.file.buffer);
      });
      avatarUrl = uploadResult.secure_url;
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ 
      username, 
      passwordHash: hashed, 
      avatarUrl,
      lastSeen: new Date()
    });
    await user.save();

    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.avatarUrl = user.avatarUrl;
    req.session.pendingUsername = null;
    
    // إعداد الكوكيز لحفظ تسجيل الدخول
    res.cookie('rememberMe', 'true', { maxAge: 1000 * 60 * 60 * 24 * 30 }); // 30 يوم
    res.cookie('userId', user._id.toString(), { maxAge: 1000 * 60 * 60 * 24 * 30 });
    
    res.redirect('/chat');
  } catch (err) { 
    console.error(err); 
    res.status(500).send('حدث خطأ في التسجيل'); 
  }
});

// تسجيل الدخول
app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/chat');
  }
  res.render('login', { message: null });
});

app.post('/login', async (req, res) => {
  const { username, password, rememberMe } = req.body;
  if (!username || !password) return res.render('login', { message: 'الرجاء إدخال اسم المستخدم وكلمة السر' });
  
  const user = await User.findOne({ username: username.trim() });
  if (!user) return res.render('login', { message: 'اسم المستخدم غير موجود' });
  
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.render('login', { message: 'كلمة السر غير صحيحة' });

  // تحديث آخر ظهور
  await User.findByIdAndUpdate(user._id, { 
    lastSeen: new Date()
  });

  req.session.userId = user._id;
  req.session.username = user.username;
  req.session.avatarUrl = user.avatarUrl;

  // حفظ تسجيل الدخول إذا طلب المستخدم ذلك
  if (rememberMe) {
    res.cookie('rememberMe', 'true', { maxAge: 1000 * 60 * 60 * 24 * 30 }); // 30 يوم
    res.cookie('userId', user._id.toString(), { maxAge: 1000 * 60 * 60 * 24 * 30 });
  }

  res.redirect('/chat');
});

// تسجيل الدخول التلقائي
app.post('/auto-login', async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.json({ success: false });

    const user = await User.findById(userId);
    if (!user) return res.json({ success: false });

    // تحديث آخر ظهور
    await User.findByIdAndUpdate(user._id, { 
      lastSeen: new Date()
    });

    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.avatarUrl = user.avatarUrl;

    res.json({ success: true, username: user.username });
  } catch (error) {
    console.error('Auto-login error:', error);
    res.json({ success: false });
  }
});

// تسجيل الخروج
app.get('/logout', (req, res) => {
  if (req.session.userId) {
    User.findByIdAndUpdate(req.session.userId, { 
      lastSeen: new Date()
    }).exec();
  }
  
  // مسح الكوكيز
  res.clearCookie('rememberMe');
  res.clearCookie('userId');
  res.clearCookie('connect.sid');
  
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).send('خطأ في تسجيل الخروج');
    }
    res.redirect('/login');
  });
});

// --- البروفايل والإعدادات ---

// صفحة البروفايل
app.get('/profile', requireLogin, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    
    // جلب إحصائيات المستخدم
    const friendsCount = await Friendship.countDocuments({
      $or: [
        { requester: req.session.userId, status: 'accepted' },
        { recipient: req.session.userId, status: 'accepted' }
      ]
    });

    const messagesCount = await Message.countDocuments({
      $or: [
        { userId: req.session.userId },
        { toUserId: req.session.userId }
      ]
    });

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
    res.status(500).send('حدث خطأ في تحميل البروفايل');
  }
});

// تحديث البروفايل
app.post('/update-profile', requireLogin, upload.single('avatar'), async (req, res) => {
  try {
    const { username } = req.body;
    const user = await User.findById(req.session.userId);
    
    let message = null;
    let success = null;

    // التحقق من أن اسم المستخدم غير مأخوذ
    if (username && username !== user.username) {
      const existingUser = await User.findOne({ username: username.trim() });
      if (existingUser) {
        message = 'اسم المستخدم مستخدم بالفعل';
      } else {
        user.username = username;
        req.session.username = username;
        success = 'تم تحديث البروفايل بنجاح';
      }
    }

    // تحديث الصورة إذا تم رفع جديدة
    if (req.file) {
      const uploadResult = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream({ folder: 'chat-avatars' }, (err, result) => {
          if (err) reject(err); else resolve(result);
        });
        stream.end(req.file.buffer);
      });
      user.avatarUrl = uploadResult.secure_url;
      req.session.avatarUrl = uploadResult.secure_url;
      success = 'تم تحديث البروفايل بنجاح';
    }

    if (!message) {
      await user.save();
    }

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
      passwordError: null
    });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).send('حدث خطأ في تحديث البروفايل');
  }
});

// تحديث كلمة السر
app.post('/update-password', requireLogin, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.session.userId);
    
    const match = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!match) {
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
        passwordError: 'كلمة السر الحالية غير صحيحة'
      });
    }

    if (newPassword.length < 4) {
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
        passwordError: 'كلمة السر الجديدة يجب أن تكون 4 أحرف على الأقل'
      });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await user.save();
    
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
      passwordError: null
    });
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).send('حدث خطأ في تحديث كلمة السر');
  }
});

// الشات العام
app.get('/chat', requireLogin, async (req, res) => {
  try {
    const messages = await Message.find({ toUserId: null })
      .populate('userId', 'username avatarUrl')
      .sort({ createdAt: 1 })
      .lean();

    res.render('chat', {
      username: req.session.username,
      avatarUrl: req.session.avatarUrl,
      messages: messages.map(msg => ({
        ...msg,
        username: msg.userId.username,
        avatarUrl: msg.userId.avatarUrl,
        userId: msg.userId._id.toString()
      })),
      userId: req.session.userId.toString()
    });
  } catch (error) {
    console.error('Error loading chat:', error);
    res.status(500).send('حدث خطأ في تحميل الشات');
  }
});

// --- المستخدمون والأصدقاء ---

// عرض جميع المستخدمين لإرسال طلب صداقة
app.get('/users', requireLogin, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.session.userId } }).lean();
    
    // الحصول على جميع طلبات الصداقة المرسلة والمستلمة
    const sentRequests = await Friendship.find({ requester: req.session.userId }).lean();
    const receivedRequests = await Friendship.find({ recipient: req.session.userId }).lean();
    const friends = await Friendship.find({
      $or: [
        { requester: req.session.userId, status: 'accepted' },
        { recipient: req.session.userId, status: 'accepted' }
      ]
    }).lean();

    const sentIds = sentRequests.map(r => r.recipient.toString());
    const receivedIds = receivedRequests.map(r => r.requester.toString());
    const friendIds = friends.map(f => {
      if (f.requester.toString() === req.session.userId.toString()) {
        return f.recipient.toString();
      } else {
        return f.requester.toString();
      }
    });

    res.render('users', { 
      users, 
      sentIds, 
      receivedIds, 
      friendIds,
      username: req.session.username,
      avatarUrl: req.session.avatarUrl
    });
  } catch (error) {
    console.error('Error in /users:', error);
    res.status(500).send('حدث خطأ في تحميل المستخدمين');
  }
});

// إرسال طلب صداقة
app.post('/friend-request/:id', requireLogin, async (req, res) => {
  try {
    const recipientId = req.params.id;

    // التحقق من عدم إرسال طلب لنفس المستخدم
    if (recipientId === req.session.userId.toString()) {
      return res.status(400).send('لا يمكن إرسال طلب صداقة لنفسك');
    }

    // التحقق من وجود طلب مسبق
    const exists = await Friendship.findOne({
      $or: [
        { requester: req.session.userId, recipient: recipientId },
        { requester: recipientId, recipient: req.session.userId }
      ]
    });

    if (exists) {
      return res.status(400).send('تم إرسال طلب مسبقاً أو أنكم أصدقاء بالفعل');
    }

    const request = new Friendship({ 
      requester: req.session.userId, 
      recipient: recipientId 
    });
    await request.save();
    res.redirect('/users');
  } catch (error) {
    console.error('Error sending friend request:', error);
    res.status(500).send('حدث خطأ في إرسال طلب الصداقة');
  }
});

// عرض الطلبات المعلقة
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
      avatarUrl: req.session.avatarUrl
    });
  } catch (error) {
    console.error('Error fetching friend requests:', error);
    res.status(500).send('حدث خطأ في تحميل طلبات الصداقة');
  }
});

// قبول الطلب
app.post('/friend-accept/:id', requireLogin, async (req, res) => {
  try {
    const requesterId = req.params.id;
    const friendship = await Friendship.findOne({ 
      requester: requesterId, 
      recipient: req.session.userId,
      status: 'pending'
    });
    
    if (!friendship) return res.status(404).send('الطلب غير موجود');
    
    friendship.status = 'accepted';
    await friendship.save();
    res.redirect('/friend-requests');
  } catch (error) {
    console.error('Error accepting friend request:', error);
    res.status(500).send('حدث خطأ في قبول طلب الصداقة');
  }
});

// رفض طلب صداقة
app.post('/friend-reject/:id', requireLogin, async (req, res) => {
  try {
    const requesterId = req.params.id;
    await Friendship.findOneAndDelete({ 
      requester: requesterId, 
      recipient: req.session.userId 
    });
    res.redirect('/friend-requests');
  } catch (error) {
    console.error('Error rejecting friend request:', error);
    res.status(500).send('حدث خطأ في رفض طلب الصداقة');
  }
});

// إلغاء طلب صداقة
app.post('/friend-cancel/:id', requireLogin, async (req, res) => {
  try {
    const recipientId = req.params.id;
    await Friendship.findOneAndDelete({ 
      requester: req.session.userId, 
      recipient: recipientId 
    });
    res.redirect('/users');
  } catch (error) {
    console.error('Error canceling friend request:', error);
    res.status(500).send('حدث خطأ في إلغاء طلب الصداقة');
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
      avatarUrl: req.session.avatarUrl
    });
  } catch (error) {
    console.error('Error fetching friends:', error);
    res.status(500).send('حدث خطأ في تحميل قائمة الأصدقاء');
  }
});

// شات خاص
app.get('/chat-private/:id', requireLogin, async (req, res) => {
  try {
    const friendId = req.params.id;
    const friendship = await Friendship.findOne({
      $or: [
        { requester: req.session.userId, recipient: friendId, status: 'accepted' },
        { requester: friendId, recipient: req.session.userId, status: 'accepted' }
      ]
    }).populate('requester recipient');

    if (!friendship) return res.status(403).send('لا يمكنك الدردشة مع هذا المستخدم');

    const messages = await Message.find({
      $or: [
        { userId: req.session.userId, toUserId: friendId },
        { userId: friendId, toUserId: req.session.userId }
      ]
    })
    .populate('userId', 'username avatarUrl')
    .sort({ createdAt: 1 })
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
      avatarUrl: req.session.avatarUrl || '/default-avatar.png'
    });
  } catch (error) {
    console.error('Error in private chat:', error);
    res.status(500).send('حدث خطأ في تحميل المحادثة');
  }
});

// --- Socket.IO ---
const io = require('socket.io')(server);

// استخدام session middleware مع Socket.IO
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

io.on('connection', async (socket) => {
  const session = socket.request.session;
  
  if (!session.userId) {
    console.log('User not authenticated - disconnecting socket');
    socket.disconnect();
    return;
  }

  console.log('User connected:', session.username, 'Socket ID:', socket.id);

  // انضمام إلى غرفة المستخدم
  socket.join(session.userId.toString());

  // الشات العام
  socket.on('chat message', async (data) => {
    try {
      console.log('Received chat message:', data);
      
      if (!data.text || data.text.trim() === '') {
        return;
      }

      const user = await User.findById(session.userId);
      if (!user) {
        console.log('User not found');
        return;
      }

      const msgData = {
        userId: session.userId,
        username: user.username,
        avatarUrl: user.avatarUrl,
        text: data.text.trim(),
        toUserId: null
      };

      const message = new Message(msgData);
      await message.save();

      console.log('Message saved, broadcasting to all users');

      // إرسال الرسالة لجميع المستخدمين المتصلين
      io.emit('chat message', {
        ...msgData,
        _id: message._id,
        createdAt: message.createdAt
      });

    } catch (error) {
      console.error('Error handling chat message:', error);
    }
  });

  // الرسائل الخاصة
  socket.on('private message', async (data) => {
    try {
      console.log('Received private message:', data);
      
      if (!data.text || data.text.trim() === '' || !data.toUserId) {
        return;
      }

      const user = await User.findById(session.userId);
      if (!user) {
        console.log('User not found');
        return;
      }

      const msgData = {
        userId: session.userId,
        username: user.username,
        avatarUrl: user.avatarUrl,
        text: data.text.trim(),
        toUserId: data.toUserId
      };

      const message = new Message(msgData);
      await message.save();

      console.log('Private message saved, sending to users:', session.userId, 'and', data.toUserId);

      // إرسال الرسالة للمستخدم المرسل والمستقبل فقط
      socket.emit('private message', {
        ...msgData,
        _id: message._id,
        createdAt: message.createdAt
      });

      socket.to(data.toUserId).emit('private message', {
        ...msgData,
        _id: message._id,
        createdAt: message.createdAt
      });

    } catch (error) {
      console.error('Error handling private message:', error);
    }
  });

  // عند انقطاع الاتصال
  socket.on('disconnect', () => {
    console.log('User disconnected:', session.username, 'Socket ID:', socket.id);
  });

  // معالجة الأخطاء
  socket.on('error', (error) => {
    console.error('Socket error:', error);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));