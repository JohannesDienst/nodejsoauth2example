var mongoose = require('mongoose');
var bcrypt = require('bcrypt-nodejs');

var userSchema = mongoose.Schema({

  username: {
    type: String,
    unique: true,
    required: true
  },
  hashedPassword: {
    type: String,
    required: true
  },
  salt: {
    type: String,
    required: true
  }/*,
  created: {
    type: Date,
    default: Date.now
  }*/

}, { collection: 'usercollection' });

userSchema.methods.encryptPassword = function(password) {
  return bcrypt.hashSync(password, this.salt, null);
};

userSchema.virtual('userId')
  .get(function () {
    return this.id;
  });
    
userSchema.virtual('password')
  .set(function(password) {
    this._plainPassword = password;
    this.salt = bcrypt.genSaltSync(8);
    this.hashedPassword = this.encryptPassword(password);
  })
  .get(function() { return this._plainPassword; });

userSchema.methods.validPassword = function(password) {
  return this.encryptPassword(password) === this.hashedPassword;
};

module.exports = mongoose.model('User', userSchema);
