const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  username: { type: String, required: true },
  avatarUrl: { type: String },
  text: { type: String, required: true },
  toUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  createdAt: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', MessageSchema);
module.exports.Message = Message;
