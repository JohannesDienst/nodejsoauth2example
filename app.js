var express = require('express');
var path = require('path');
var favicon = require('static-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var session = require('express-session');

var mongoose = require('mongoose');
var config = require('./config/config');
mongoose.connect(config.databaseurl);

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

var stylus = require('stylus');
var nib = require('nib');
function compile(str, path) {
  return stylus(str)
    .set('filename', path)
    .use(nib());
}
app.use(stylus.middleware(
  {
	src: __dirname + '/public',
	compile: compile
  }
));

app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(methodOverride());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

var passport = require('passport');
require('./config/passport')(passport);
app.use(passport.initialize());

app.use(session({ secret: 'eingeheimersecret' }));
app.use(passport.initialize());
app.use(passport.session());

var server = require('./config/oauth2');

var routes = require('./routes/index')(passport, app, server);

/// catch 404 and forward to error handler
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

/// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});


module.exports = app;
