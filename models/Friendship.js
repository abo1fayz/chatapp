const mongoose = require('mongoose');

const FriendshipSchema = new mongoose.Schema({
  requester: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['pending','accepted'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const Friendship = mongoose.model('Friendship', FriendshipSchema);
module.exports.Friendship = Friendship;
