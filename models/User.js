const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true
  },
  passwordHash: { 
    type: String, 
    required: true 
  },
  avatarUrl: { 
    type: String,
    default: null
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  isBanned: {
    type: Boolean,
    default: false
  },
  settings: {
    allowFriendRequests: { type: Boolean, default: true },
    showOnlineStatus: { type: Boolean, default: true }
  }
}, { 
  timestamps: true 
});

userSchema.virtual('isOnline').get(function() {
  return Date.now() - this.lastSeen.getTime() < 5 * 60 * 1000;
});

userSchema.virtual('lastSeenFormatted').get(function() {
  const now = new Date();
  const diff = now - this.lastSeen;
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (minutes < 1) return 'الآن';
  if (minutes < 60) return `منذ ${minutes} دقيقة`;
  if (hours < 24) return `منذ ${hours} ساعة`;
  if (days < 7) return `منذ ${days} يوم`;
  return this.lastSeen.toLocaleDateString('ar-SA');
});

const User = mongoose.model('User', userSchema);
module.exports.User = User;
