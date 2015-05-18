var User = require('../models/user');

module.exports = function(passport, app, server) {

  app.get('/', function(req, res) {
    req.logout();
    res.render('index', {});
  });

  app.get('/login', function(req, res) {
    req.logout();
    res.render('login', { title: 'User Login' });
  });

  app.post('/dologin',
    passport.authenticate('local-login', {
      successRedirect : '/account',
      failureRedirect : '/login'
    })
  );
  
  app.get('/register', function(req, res) {
    res.render('register', { title: 'Register' });
  });

  app.get('/connect/local', function(req, res) {
    res.render('connect-local.jade');
  });
  app.post('/connect/local',
    passport.authenticate('local-signup', {
      successRedirect : '/account',
      failureRedirect : '/connect/local'
    })
  );
  app.get('/unlink/local', function(req, res) {
    var user = req.user;
    user.local.email = undefined;
    user.local.password = undefined;
    user.save(function(err) {
      res.redirect('/account');
    });
  });
  
  app.post('/doregister',
    passport.authenticate('local-signup',
      {
        successRedirect : '/account',
        failureRedirect : '/register'
      })
  );

  app.get('/account', ensureAuthenticated, function(req, res){
    res.render('account', { user: req.user });
  });

  app.get('/auth/twitter', passport.authenticate('twitter') );
  app.get('/auth/twitter/callback',
    passport.authenticate('twitter',
      {
        successRedirect : '/account',
        failureRedirect: '/' 
      })
  );
  app.get('/connect/twitter', passport.authorize('twitter', { scope : 'email' }));
  app.get('/connect/twitter/callback',
    passport.authenticate('twitter', {
      successRedirect : '/account',
      failureRedirect : '/'
    })
  );
  app.get('/unlink/twitter', function(req, res) {
    var user = req.user;
    user.twitter.token = undefined;
    user.save(function(err) {
      res.redirect('/account');
    });
  });

  app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
  app.get('/auth/google/callback',
    passport.authenticate('google',
      {
        successRedirect : '/account',
        failureRedirect: '/' 
      })
  );
  app.get('/connect/google', passport.authorize('google', { scope : ['profile', 'email'] }));
  app.get('/connect/google/callback',
    passport.authenticate('google', {
      successRedirect : '/account',
      failureRedirect : '/'
    })
  );
  app.get('/unlink/google', function(req, res) {
    var user = req.user;
    user.google.token = undefined;
    user.save(function(err) {
      res.redirect('/account');
    });
  });

  app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/');
  });

  app.post(
    '/token', 
    [passport.authenticate(
     ['oauth2-client-password'], // 'basic', 
     { session: false }),
     server.token(),
     server.errorHandler()]
  )
  
  app.post('/api/userInfo',
    passport.authenticate('bearer', { session: false }),
      function(req, res) {
        res.json({ user_id: req.user.userId, name: req.user.username, scope: req.authInfo.scope })
      }
  );

};

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated())
  {
    return next();
  }
  res.redirect('/');
}
