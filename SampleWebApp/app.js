/**
 * Copyright (c) Microsoft Corporation
 *  All Rights Reserved
 *  MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the 'Software'), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
 * OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

'use strict';

/******************************************************************************
 * Module dependencies.
 *****************************************************************************/

const express = require('express');
const cookieParser = require('cookie-parser');
const expressSession = require('express-session');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');
const passport = require('passport');
const morgan = require('morgan');
const bunyan = require('bunyan');
const path = require('path');
const {
  creds: {
    identityMetadata,
    clientID,
    responseType,
    responseMode,
    redirectUrl,
    allowHttpForRedirectUrl,
    clientSecret,
    validateIssuer,
    isB2C,
    issuer,
    jweKeyStore,
    passReqToCallback,
    scope,
    loggingLevel,
    nonceLifetime,
    nonceMaxAmount,
    useCookieInsteadOfSession,
    cookieEncryptionKeys,
    clockSkew,
  },
  useMongoDBSessionStore,
  databaseUri,
  mongoDBSessionMaxAge,
  resourceURL,
  destroySessionUrl,
  port,
} = require('./config');

// set up database for express session
const MongoStore = require('connect-mongo')(expressSession);
const mongoose = require('mongoose');

// Start QuickStart here

const { OIDCStrategy } = require('passport-azure-ad');

const log = bunyan.createLogger({
  name: 'Microsoft OIDC Example Web Application',
});

/******************************************************************************
 * Set up passport in the app
 ******************************************************************************/

//-----------------------------------------------------------------------------
// To support persistent login sessions, Passport needs to be able to
// serialize users into and deserialize users out of the session.  Typically,
// this will be as simple as storing the user ID when serializing, and finding
// the user by ID when deserializing.
//-----------------------------------------------------------------------------
passport.serializeUser((user, done) => done(null, user.oid));

passport.deserializeUser((oid, done) =>
  findByOid(oid, (err, user) => done(err, user))
);

// array to hold logged in users
const users = [];

const findByOid = (oid, fn) => {
  const length = users.length;
  for (let i = 0; i < length; i++) {
    const user = users[i];
    log.info('we are using user: ', user);
    if (user.oid === oid) {
      return fn(null, user);
    }
  }
  return fn(null, null);
};

//-----------------------------------------------------------------------------
// Use the OIDCStrategy within Passport.
//
// Strategies in passport require a `verify` function, which accepts credentials
// (in this case, the `oid` claim in id_token), and invoke a callback to find
// the corresponding user object.
//
// The following are the accepted prototypes for the `verify` function
// (1) function(iss, sub, done)
// (2) function(iss, sub, profile, done)
// (3) function(iss, sub, profile, access_token, refresh_token, done)
// (4) function(iss, sub, profile, access_token, refresh_token, params, done)
// (5) function(iss, sub, profile, jwtClaims, access_token, refresh_token, params, done)
// (6) prototype (1)-(5) with an additional `req` parameter as the first parameter
//
// To do prototype (6), passReqToCallback must be set to true in the config.
//-----------------------------------------------------------------------------
passport.use(
  new OIDCStrategy(
    {
      identityMetadata,
      clientID,
      responseType,
      responseMode,
      redirectUrl,
      allowHttpForRedirectUrl,
      clientSecret,
      validateIssuer,
      isB2C,
      issuer,
      jweKeyStore,
      passReqToCallback,
      scope,
      loggingLevel,
      nonceLifetime,
      nonceMaxAmount,
      useCookieInsteadOfSession,
      cookieEncryptionKeys,
      clockSkew,
    },
    (
      req,
      iss,
      sub,
      profile,
      jwtClaims,
      accessToken,
      refreshToken,
      params,
      done
    ) => {
      if (!profile.oid) {
        return done(new Error('No oid found'), null);
      }
      /* const separator = '--------------------------------';
      console.log(separator);
      console.log(`req.user: ${JSON.stringify(req.user, null, 2)}`);
      console.log(`iss: ${iss}`);
      console.log(`sub: ${sub}`);
      console.log(`jwtClaims: ${JSON.stringify(jwtClaims, null, 2)}`);
      console.log(`accessToken: ${accessToken}`);
      console.log(`refreshToken: ${refreshToken}`);
      console.log(`params: ${JSON.stringify(params, null, 2)}`);
      console.log(separator); */
      // asynchronous verification, for effect...
      process.nextTick(() => {
        findByOid(profile.oid, (err, user) => {
          if (err) {
            return done(err);
          }
          if (!user) {
            // "Auto-registration"
            users.push(profile);
            return done(null, profile);
          }
          return done(null, user);
        });
      });
    }
  )
);

//-----------------------------------------------------------------------------
// Config the app, include middlewares
//-----------------------------------------------------------------------------
const app = express();
const router = express.Router();

app.set('views', path.join(__dirname, '/views'));
app.set('view engine', 'ejs');
app.use(morgan('dev'));
app.use(methodOverride());
app.use(cookieParser());

// set up session middleware
if (useMongoDBSessionStore) {
  mongoose.connect(databaseUri);
  app.use(
    express.session({
      secret: 'secret',
      cookie: { maxAge: mongoDBSessionMaxAge * 1000 },
      store: new MongoStore({
        mongooseConnection: mongoose.connection,
        clear_interval: mongoDBSessionMaxAge,
      }),
    })
  );
} else {
  app.use(
    expressSession({
      secret: 'keyboard cat',
      resave: true,
      saveUninitialized: false,
    })
  );
}

app.use(bodyParser.urlencoded({ extended: true }));

// Initialize Passport!  Also use passport.session() middleware, to support
// persistent login sessions (recommended).
app.use(passport.initialize());
app.use(passport.session());
app.use(router);
app.use(express.static(path.join(__dirname, '/../../public')));

//-----------------------------------------------------------------------------
// Set up the route controller
//
// 1. For 'login' route and 'returnURL' route, use `passport.authenticate`.
// This way the passport middleware can redirect the user to login page, receive
// id_token etc from returnURL.
//
// 2. For the routes you want to check if user is already logged in, use
// `ensureAuthenticated`. It checks if there is an user stored in session, if not
// it will call `passport.authenticate` to ask for user to log in.
//-----------------------------------------------------------------------------
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

router.get('/', (req, res) => res.render('index', { user: req.user }));

// '/account' is only available to logged in user
router.get('/account', ensureAuthenticated, (req, res) =>
  res.render('account', { user: req.user })
);

router.get(
  '/login',
  (req, res, next) =>
    passport.authenticate('azuread-openidconnect', {
      response: res, // required
      resourceURL: resourceURL, // optional. Provide a value if you want to specify the resource.
      customState: 'my_state', // optional. Provide a value if you want to provide custom state value.
      failureRedirect: '/',
    })(req, res, next),
  (req, res) => {
    log.info('Login was called in the Sample');
    res.redirect('/');
  }
);

// 'GET returnURL'
// `passport.authenticate` will try to authenticate the content returned in
// query (such as authorization code). If authentication fails, user will be
// redirected to '/' (home page); otherwise, it passes to the next middleware.
router.get(
  '/auth/openid/return',
  (req, res, next) => {
    passport.authenticate('azuread-openidconnect', {
      response: res, // required
      failureRedirect: '/',
    })(req, res, next);
  },
  (req, res) => {
    log.info('We received a return from AzureAD.');
    res.redirect('/');
  }
);

// 'POST returnURL'
// `passport.authenticate` will try to authenticate the content returned in
// body (such as authorization code). If authentication fails, user will be
// redirected to '/' (home page); otherwise, it passes to the next middleware.
router.post(
  '/auth/openid/return',
  (req, res, next) => {
    passport.authenticate('azuread-openidconnect', {
      response: res, // required
      failureRedirect: '/',
    })(req, res, next);
  },
  (req, res) => {
    log.info('We received a return from AzureAD.');
    res.redirect('/');
  }
);

// 'logout' route, logout from passport, and destroy the session with AAD.
router.get('/logout', (req, res) =>
  req.session.destroy((error) => {
    if (error) {
      throw new Error(error);
    }

    req.logOut();
    res.redirect(destroySessionUrl);
  })
);

app.listen(3000, () =>
  console.log(`app listening at http://localhost:${port}`)
);
