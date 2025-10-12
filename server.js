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
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser:true, useUnifiedTopology:true })
  .then(()=> console.log('MongoDB connected'))
  .catch(err => console.error(err));

// --- Session ---
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'secret123',
  resave:false,
  saveUninitialized:false,
  store: MongoStore.create({ mongoUrl:process.env.MONGODB_URI }),
  cookie: { maxAge: 1000*60*60*24 }
});
app.use(sessionMiddleware);

// --- EJS ---
app.set('view engine','ejs');
app.set('views', path.join(__dirname,'views'));

// --- Static ---
app.use(express.static(path.join(__dirname,'public')));
app.use(express.urlencoded({ extended:true }));
app.use(express.json());

// --- Cloudinary ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// --- Multer ---
const upload = multer({ storage: multer.memoryStorage() });

// --- Middleware ---
function requireLogin(req,res,next){
  if(!req.session.userId) return res.redirect('/login');
  next();
}

// --- Routes ---

// الصفحة الرئيسية
app.get('/', (req,res)=>res.render('index',{ message:null }));

// التحقق من اسم المستخدم
app.post('/check-username', async(req,res)=>{
  const { username } = req.body;
  if(!username) return res.render('index',{ message:'الرجاء إدخال اسم مستخدم' });
  const exists = await User.findOne({ username:username.trim() });
  if(exists) return res.render('index',{ message:'الاسم مستخدم بالفعل' });
  req.session.pendingUsername = username.trim();
  res.redirect('/set-password');
});

// صفحة كلمة السر وصورة البروفايل
app.get('/set-password',(req,res)=>{
  if(!req.session.pendingUsername) return res.redirect('/');
  res.render('password',{ username:req.session.pendingUsername, message:null });
});

// التسجيل
app.post('/register', upload.single('avatar'), async(req,res)=>{
  try{
    const username = req.session.pendingUsername;
    if(!username) return res.redirect('/');
    const { password } = req.body;
    if(!password || password.length<4) return res.render('password',{ username, message:'كلمة السر قصيرة' });

    let avatarUrl = null;
    if(req.file){
      const uploadResult = await new Promise((resolve,reject)=>{
        const stream = cloudinary.uploader.upload_stream({ folder:'chat-avatars' }, (err,result)=>{
          if(err) reject(err); else resolve(result);
        });
        stream.end(req.file.buffer);
      });
      avatarUrl = uploadResult.secure_url;
    }

    const hashed = await bcrypt.hash(password,10);
    const user = new User({ username, passwordHash:hashed, avatarUrl });
    await user.save();

    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.avatarUrl = user.avatarUrl;
    req.session.pendingUsername = null;
    res.redirect('/chat');
  }catch(err){ console.error(err); res.status(500).send('حدث خطأ'); }
});

// تسجيل الدخول
app.get('/login',(req,res)=>res.render('login',{ message:null }));

app.post('/login', async(req,res)=>{
  const { username,password } = req.body;
  if(!username || !password) return res.render('login',{ message:'الرجاء إدخال اسم المستخدم وكلمة السر' });
  const user = await User.findOne({ username:username.trim() });
  if(!user) return res.render('login',{ message:'اسم المستخدم غير موجود' });
  const match = await bcrypt.compare(password,user.passwordHash);
  if(!match) return res.render('login',{ message:'كلمة السر غير صحيحة' });

  req.session.userId = user._id;
  req.session.username = user.username;
  req.session.avatarUrl = user.avatarUrl;
  res.redirect('/chat');
});

// تسجيل الخروج
app.get('/logout',(req,res)=>{
  req.session.destroy(err=>{ if(err) return res.status(500).send('خطأ'); res.redirect('/login'); });
});

// الشات العام
app.get('/chat', requireLogin, async(req,res)=>{
  const messages = await Message.find({ toUserId:null }).sort({ createdAt:1 }).lean();
  res.render('chat',{
    username:req.session.username,
    avatarUrl:req.session.avatarUrl,
    messages,
    userId:req.session.userId.toString()
  });
});

// --- المستخدمون والأصدقاء ---
// عرض جميع المستخدمين لإرسال طلب صداقة
app.get('/users', requireLogin, async(req,res)=>{
  const users = await User.find({ _id: { $ne: req.session.userId } }).lean();
  const sentRequests = await Friendship.find({ requester: req.session.userId }).lean();
  const sentIds = sentRequests.map(r => r.recipient.toString());
  res.render('users',{ users, sentIds });
});

// إرسال طلب صداقة
app.post('/friend-request/:id', requireLogin, async(req,res)=>{
  const recipientId = req.params.id;
  const exists = await Friendship.findOne({ requester:req.session.userId, recipient:recipientId });
  if(exists) return res.status(400).send('تم إرسال طلب مسبقاً');
  const request = new Friendship({ requester:req.session.userId, recipient:recipientId });
  await request.save();
  res.redirect('/users');
});

// عرض الطلبات المعلقة
app.get('/friend-requests', requireLogin, async(req,res)=>{
  const requests = await Friendship.find({ recipient:req.session.userId, status:'pending' }).populate('requester').lean();
  res.render('friend-requests',{ requests });
});

// قبول الطلب
app.post('/friend-accept/:id', requireLogin, async(req,res)=>{
  const requesterId = req.params.id;
  const friendship = await Friendship.findOne({ requester:requesterId, recipient:req.session.userId });
  if(!friendship) return res.status(404).send('الطلب غير موجود');
  friendship.status = 'accepted';
  await friendship.save();
  res.redirect('/friend-requests');
});

// عرض الأصدقاء
app.get('/friends', requireLogin, async(req,res)=>{
  const friends = await Friendship.find({
    $or:[
      { requester:req.session.userId, status:'accepted' },
      { recipient:req.session.userId, status:'accepted' }
    ]
  }).populate('requester recipient').lean();

  const friendList = friends.map(f=>{
    if(f.requester._id.toString()===req.session.userId.toString()) return f.recipient;
    return f.requester;
  });

  res.render('friends',{ friends:friendList });
});

// شات خاص
app.get('/chat-private/:id', requireLogin, async(req,res)=>{
  const friendId = req.params.id;
  const friendship = await Friendship.findOne({
    $or:[
      { requester:req.session.userId, recipient:friendId, status:'accepted' },
      { requester:friendId, recipient:req.session.userId, status:'accepted' }
    ]
  });
  if(!friendship) return res.status(403).send('لا يمكنك الدردشة مع هذا المستخدم');

  const messages = await Message.find({
    $or:[
      { userId:req.session.userId, toUserId:friendId },
      { userId:friendId, toUserId:req.session.userId }
    ]
  }).sort({ createdAt:1 }).lean();

  res.render('chat-private',{
    messages,
    friendId,
    friendUsername: friendship.requester._id.toString()===friendId? friendship.requester.username : friendship.recipient.username,
    userId:req.session.userId.toString(),
    avatarUrl: req.session.avatarUrl || '/default-avatar.png'  // تم إضافة هذا السطر
  });
});

// --- Socket.IO ---
const io = require('socket.io')(server);
io.use((socket,next)=> sessionMiddleware(socket.request,{},next));

io.on('connection', socket=>{
  const session = socket.request.session;
  if(!session.userId) return;

  socket.on('chat message', async(data)=>{
    const msgData = { userId:session.userId, username:session.username, avatarUrl:session.avatarUrl, text:data.text, toUserId:null };
    const message = new Message(msgData);
    await message.save();
    io.emit('chat message', msgData);
  });

  socket.on('private message', async(data)=>{
    const msgData = { userId:session.userId, username:session.username, avatarUrl:session.avatarUrl, text:data.text, toUserId:data.toUserId };
    const message = new Message(msgData);
    await message.save();

    for(let [id,s] of io.sockets.sockets){
      const sockSession = s.request.session;
      if(sockSession.userId.toString()===data.toUserId || sockSession.userId.toString()===session.userId.toString()){
        s.emit('private message', msgData);
      }
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, ()=>console.log(`Server running on http://localhost:${PORT}`));
