var mongoose = require('mongoose');

var RefreshToken = new mongoose.Schema({
    userId: {
      type: String,
      required: true
    },
    clientId: {
      type: String,
      required: true
    },
    token: {
      type: String,
      unique: true,
      required: true
    },
    created: {
      type: Date,
      default: Date.now
    }
}, { collection: 'refreshtokencollection' });

module.exports = mongoose.model('RefreshToken', RefreshToken);
