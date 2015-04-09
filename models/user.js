var mongoose = require('mongoose');
var bcrypt = require('bcrypt-nodejs');

var userSchema = mongoose.Schema({

  local : {
//    username: {
//      type: String,
//      unique: true
//    },
    password : {
      type: String
    },
    email : {
      type: String
    },
    salt: {
      type: String
    }
  },

  hashedPassword: {
    type: String
  },
  salt: {
    type: String
  },

  twitter : {
    id : String,
    token : String,
    displayName : String,
    username : String
  },
  google : {
    id : String,
    token : String,
    email : String,
    name : String
  }

}, { collection: 'usercollection' });

userSchema.methods.encryptPassword = function(password) {
  return bcrypt.hashSync(password, this.salt, null);
};

userSchema.methods.encryptLocalPassword = function(password) {
  return bcrypt.hashSync(password, this.local.salt, null);
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

userSchema.methods.generateHash = function(password) {
  this.local.salt = bcrypt.genSaltSync(8);
  return bcrypt.hashSync(password, this.local.salt, null);
};

userSchema.methods.validLocalPassword = function(password) {
  return this.encryptLocalPassword(password) === this.local.password;
};

userSchema.methods.validPassword = function(password) {
  return this.encryptPassword(password) === this.hashedPassword;
};

module.exports = mongoose.model('User', userSchema);
