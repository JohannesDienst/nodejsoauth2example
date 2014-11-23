module.exports = function(passport, app, server) {

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
