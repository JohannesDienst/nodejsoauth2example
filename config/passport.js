var bcrypt = require('bcrypt-nodejs');
var User = require('../models/user');

var config = require('../config/config');
//var BasicStrategy = require('passport-http').BasicStrategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
var BearerStrategy = require('passport-http-bearer').Strategy;
var UserModel = require('../models/user');
var ClientModel = require('../models/client');
var AccessTokenModel = require('../models/accesstoken');
var RefreshTokenModel = require('../models/refreshtoken');

module.exports = function(passport) {

  /* TODO Wird gebraucht?
  passport.use('basic', new BasicStrategy(
    function(username, password, done) {

        ClientModel.findOne({ 'clientId' : username }, function(err, client) {
            if (err) {
              return done(err);
            }
            if (!client) {
              return done(null, false);
            }
            if (client.clientSecret != password) {
              return done(null, false);
            }

            return done(null, client);
        });
    }
  )); */
  
  passport.use('oauth2-client-password', new ClientPasswordStrategy(
    function(clientId, clientSecret, done) {
      ClientModel.findOne({ clientId: clientId }, function(err, client) {
        if (err) {
          return done(err);
        }
        if (!client) {
          return done(null, false);
        }
        if (client.clientSecret != clientSecret) {
          return done(null, false);
        }

        return done(null, client);
      });
    }
  ));
  
  passport.use('bearer', new BearerStrategy(
    function(accessToken, done) {

        AccessTokenModel.findOne({ token: accessToken }, function(err, token) {

            if (err) {
              return done(err);
            }
            if (!token) {
              return done(null, false);
            }

            if( Math.round((Date.now()-token.created)/1000) > config.security.tokenLife ) {
              AccessTokenModel.remove({ token: accessToken }, function (err) {
                  if (err) {
                    return done(err);
                  }
                });
                return done(null, false, { message: 'Token expired' });
            }

            UserModel.findById(token.userId, function(err, user) {
                if (err) {
                  return done(err);
                }
                if (!user) {
                  return done(null, false, { message: 'Unknown user' });
                }

                var info = { scope: '*' }
                done(null, user, info);
            });
        });
    }
  ));

};
