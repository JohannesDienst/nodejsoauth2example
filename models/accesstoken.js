var mongoose = require('mongoose');

var AccessToken = new mongoose.Schema({
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
}, { collection: 'accesstokencollection' });

module.exports = mongoose.model('AccessToken', AccessToken);
