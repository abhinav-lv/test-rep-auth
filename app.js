// TODO:
// 1. Implement CSRF protection
// 2. Error handling, wherever required

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const {google} = require('googleapis');
const jwt_decode = require('jwt-decode');
const RedisStore = require('connect-redis').default;
const {createClient} = require('redis');

const app = express();

// Initialize redis client
const redisClient = createClient();
redisClient.connect().catch(console.error);
// Initialize store
const redisStore = new RedisStore({
    client: redisClient,
    prefix: process.env.REDIS_PREFIX,
});

// Initialize client for google OAuth2
const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.REDIRECT_URL
);
// Required scopes
const scopes = [
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
];
// Generating consent URL
const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes
});

// Middleware
app.use(express.urlencoded({ extended: false })); 
app.use(session({
    store: redisStore,
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {secure: false, maxAge: 15*60*1000} // 15 minutes
}));

// middleware to test if authenticated
function isAuthenticated (req, res, next) {
    if (req.session.user) next();
    else res.redirect('/');
  }

// Root route
app.get('/',(req,res) => {

    if(req.session.user) res.redirect('/dashboard');
    /* set secure to true when pushing to production */
    // res.cookie('heyCookie', 'I am your first yummy cookie!', {maxAge: 12000, httpOnly: true, secure: false});
    // console.log(req.session);

    else res.send(`<a href=${url}>Login with Google</a>`);
});

// Callback route for google oauth
app.get('/login', async (req,res) => {
    
    // Retrieve code query
    const code = req.query.code;

    // Get access, id and refresh tokens by exchanging code
    const {tokens} = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Get user object by decoding the id_token
    const user = jwt_decode(tokens.id_token);
    // console.log(user);

    // create session for the user
    req.session.regenerate((err) => {
        if(err) next(err);
        const t = user.name.split(' ');
        req.session.user = {
            regNo: t[t.length-1],
            name: t.slice(0,-1).join(' '),
            email: user.email
        };
        res.redirect('/dashboard');
    });
});

// Dashboard for user
app.get('/dashboard', isAuthenticated, (req,res) => {
    // console.log(req.session.id);
    // console.log(req.sessionStore);
    res.send('Hello, You are signed in.');
});

// Logout route
app.get('/logout', isAuthenticated, (req,res,next) => {
    req.session.destroy((err) => {
        if(err) next(err);
        res.clearCookie("connect.sid");
        res.redirect('/');
    });
});

module.exports = app;