const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  avatarUrl: { type: String }
});

const User = mongoose.model('User', UserSchema);
module.exports.User = User;
