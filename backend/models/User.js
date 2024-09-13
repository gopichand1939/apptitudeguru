const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
   email: { type: String, required: true, unique: true },
   password: { type: String, required: true },
   role: { type: String, enum: ['Admin', 'User', 'Recruiter'], required: true },
   status: { type: String, enum: ['pending', 'approved'], default: 'pending' },
   mfa_enabled: { type: Boolean, default: false },
   mfa_token: { type: String, default: null },
   created_at: { type: Date, default: Date.now },
   updated_at: { type: Date, default: Date.now },
});

// Encrypt password before saving
UserSchema.pre('save', async function (next) {
   if (!this.isModified('password')) return next();
   const salt = await bcrypt.genSalt(10);
   this.password = await bcrypt.hash(this.password, salt);
   next();
});

module.exports = mongoose.model('User', UserSchema);
