var bcrypt = require('bcrypt-nodejs');
var User = require('../models/user');

var config = require('../config/config');
var LocalStrategy = require('passport-local').Strategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
var BearerStrategy = require('passport-http-bearer').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var UserModel = require('../models/user');
var ClientModel = require('../models/client');
var AccessTokenModel = require('../models/accesstoken');
var RefreshTokenModel = require('../models/refreshtoken');

var providerConfig = require('../config/provider');

module.exports = function(passport) {

  passport.serializeUser(function(user, done) {
    done(null, user._id);
  });

  passport.deserializeUser(function(obj, done) {
    UserModel.findById(obj, function(err, user){
      if(err) { done(err) };
      done(null, user);
    });
  });

  passport.use(new TwitterStrategy(
    {
      consumerKey: providerConfig.twitter.consumerKey,
      consumerSecret: providerConfig.twitter.consumerSecret,
      callbackURL: providerConfig.twitter.callbackURL,
      passReqToCallback : true
    },
    function(req, accessToken, refreshToken, profile, done) {
      process.nextTick(function(){

        if (!req.user) 
        {
          UserModel.findOne({ 'twitter.id': profile.id }, function(err, user) {
            if(err) 
            {
              return done(err);
            }
            if (user)
            {
              if (!user.twitter.token) 
              {
                user.twitter.token       = accessToken;
                user.twitter.username    = profile.username;
                user.twitter.displayName = profile.displayName;

                user.save(function(err) {
                  if (err)
                    throw err;
                  return done(null, user);
                });
              }

              return done(null, user);
            }
            else
            {
              var newUser                 = new UserModel();

              newUser.twitter.id          = profile.id;
              newUser.twitter.token       = accessToken;
              newUser.twitter.username    = profile.username;
              newUser.twitter.displayName = profile.displayName;

              newUser.save(function(err) {
                if (err)
                  throw err;
                return done(null, newUser);
              });
            }
          });
        }
        else
        {
           var user = req.user;

           user.twitter.id          = profile.id;
           user.twitter.token       = accessToken;
           user.twitter.username    = profile.username;
           user.twitter.displayName = profile.displayName;

           user.save(function(err) {
             if (err)
             {
               throw err;
             }
             return done(null, user);
           });
        }
      });
    }
  ));

  passport.use('local-login', new LocalStrategy(
    {
      usernameField : 'username',
      passwordField : 'password',
      passReqToCallback : true
    },
    function(req, username, password, done) {
      process.nextTick(
        function() {
          User.findOne({ 'local.email' :  username }, function(err, user) {

            if (err || !user)
            {
              return done(err);
            }

            if (!user.validLocalPassword(password))
            {
              return done(err);
            }

            return done(null, user);
          });
        }
      );
    }));

    passport.use('local-signup', new LocalStrategy({
      usernameField : 'email',
      passwordField : 'password',
      passReqToCallback : true
    },
    function(req, email, password, done) {
      process.nextTick(function() {

        User.findOne({ 'local.email': email }, function(err, theUser) {
          if (err)
          {
            return done(err);
          }
          
          if (theUser != null)
          {
            return done(err);
          }

          if (req.user)
          {
            var user = req.user;
            // user.local.username = username;
            user.local.email = req.body.email;
            user.local.password = user.generateHash(password);
            user.save(function(err) {
              if (err)
              {
                throw err;
              }
              return done(null, user);
            });
          }
          else
          {
            var newUser = new User();

            newUser.local.email = email;
            newUser.local.password = newUser.generateHash(password);

            newUser.save(function(err) {
              if (err)
                throw err;
              return done(null, newUser);
            });
          }

        });
      });

    }));

  passport.use(new GoogleStrategy({
      clientID : providerConfig.googleAuth.clientID,
      clientSecret : providerConfig.googleAuth.clientSecret,
      callbackURL : providerConfig.googleAuth.callbackURL,
      passReqToCallback : true
    },
    function(req, accessToken, refreshToken, profile, done) {
      process.nextTick(function() {
        if (!req.user) {
          User.findOne({ 'google.id' : profile.id }, function(err, user) {
            if (err)
            {
              return done(err);
            }

            if (user)
            {

              // if there is a user id already but no token (user was linked at one point and then removed)
              if (!user.google.token)
              {
                user.google.token = accessToken;
                user.google.name  = profile.displayName;
                user.google.email = profile.emails[0].value; // pull the first email

                user.save(function(err) {
                  if (err)
                    throw err;
                  return done(null, user);
                });
              }

              return done(null, user);
            }
            else
            {
              var newUser = new User();

              newUser.google.id    = profile.id;
              newUser.google.token = accessToken;
              newUser.google.name  = profile.displayName;
              newUser.google.email = profile.emails[0].value; // pull the first email

              newUser.save(function(err) {
                if (err)
                  throw err;
                return done(null, newUser);
              });
            }
          });
        }
        else
        {
          var user = req.user; // pull the user out of the session

          user.google.id    = profile.id;
          user.google.token = accessToken;
          user.google.name  = profile.displayName;
          user.google.email = profile.emails[0].value; // pull the first email

          user.save(function(err) {
            if (err)
              throw err;
            return done(null, user);
          });

        }

    });
  }));

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
