const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  username: { 
    type: String, 
    required: true 
  },
  avatarUrl: { 
    type: String 
  },
  text: { 
    type: String, 
    required: true 
  },
  toUserId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    default: null 
  },
  read: { 
    type: Boolean, 
    default: false 
  },
  readAt: { 
    type: Date,
    default: null
  },
  messageType: {
    type: String,
    enum: ['text', 'image', 'file'],
    default: 'text'
  },
  fileUrl: {
    type: String,
    default: null
  },
  fileName: {
    type: String,
    default: null
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  }
});

// تحديث updatedAt قبل الحفظ
MessageSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// فهارس لتحسين الأداء
MessageSchema.index({ userId: 1, toUserId: 1, createdAt: -1 });
MessageSchema.index({ toUserId: 1, read: 1 });
MessageSchema.index({ userId: 1, toUserId: 1, read: 1 });
MessageSchema.index({ createdAt: -1 });

// دالة افتراضية للحصول على وقت الرسالة بشكل منسق
MessageSchema.virtual('formattedTime').get(function() {
  return this.createdAt.toLocaleTimeString('ar-SA', { 
    hour: '2-digit', 
    minute: '2-digit' 
  });
});

// دالة افتراضية للحصول على تاريخ الرسالة بشكل منسق
MessageSchema.virtual('formattedDate').get(function() {
  const now = new Date();
  const diff = now - this.createdAt;
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  
  if (days === 0) {
    return 'اليوم';
  } else if (days === 1) {
    return 'أمس';
  } else if (days < 7) {
    return `منذ ${days} أيام`;
  } else {
    return this.createdAt.toLocaleDateString('ar-SA');
  }
});

// دالة لتحديث حالة القراءة
MessageSchema.methods.markAsRead = function() {
  this.read = true;
  this.readAt = new Date();
  return this.save();
};

// دالة ثابتة لتحديث مجموعة من الرسائل كمقروءة
MessageSchema.statics.markMultipleAsRead = async function(userId, toUserId) {
  return this.updateMany(
    {
      userId: toUserId,
      toUserId: userId,
      read: false
    },
    {
      $set: {
        read: true,
        readAt: new Date()
      }
    }
  );
};

// دالة ثابتة للحصول على عدد الرسائل غير المقروءة
MessageSchema.statics.getUnreadCount = async function(userId, toUserId) {
  return this.countDocuments({
    userId: toUserId,
    toUserId: userId,
    read: false
  });
};

// دالة ثابتة للحصول على آخر رسالة في المحادثة
MessageSchema.statics.getLastMessage = async function(userId1, userId2) {
  return this.findOne({
    $or: [
      { userId: userId1, toUserId: userId2 },
      { userId: userId2, toUserId: userId1 }
    ]
  })
  .sort({ createdAt: -1 })
  .select('text createdAt read messageType')
  .lean();
};

// دالة ثابتة للحصول على جميع الرسائل غير المقروءة للمستخدم
MessageSchema.statics.getAllUnreadMessages = async function(userId) {
  return this.find({
    toUserId: userId,
    read: false
  })
  .populate('userId', 'username avatarUrl')
  .sort({ createdAt: 1 })
  .lean();
};

// تأكد من إظهار الحقول الافتراضية عند التحويل إلى JSON
MessageSchema.set('toJSON', {
  virtuals: true,
  transform: function(doc, ret) {
    ret.id = ret._id;
    delete ret._id;
    delete ret.__v;
    return ret;
  }
});

const Message = mongoose.model('Message', MessageSchema);
module.exports.Message = Message;