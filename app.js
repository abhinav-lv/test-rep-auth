require('dotenv').config();
const express = require('express');
const session = require('express-session');
const {google} = require('googleapis');
const jwt_decode = require('jwt-decode');

const app = express();
const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.REDIRECT_URL
);
const scopes = [
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
];
const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes
});

app.use(express.urlencoded({ extended: false })); 
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {secure: false, maxAge: 15*60*1000} // 15 minutes
}));

// TODO:
// 1. Implement CSRF protection

// middleware to test if authenticated
function isAuthenticated (req, res, next) {
    if (req.session.user) next();
    else res.redirect('/');
  }

app.get('/',(req,res) => {

    /* set secure to true when pushing to production */
    // res.cookie('heyCookie', 'I am your first yummy cookie!', {maxAge: 12000, httpOnly: true, secure: false});
    // console.log(req.session);

    res.send(`<a href=${url}>Login with Google</a>`);
});

app.get('/login', async (req,res) => {
    
    // Retrieve code query
    const code = req.query.code;

    // Get access, id and refresh tokens by exchanging code
    const {tokens} = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    const user = jwt_decode(tokens.id_token);
    // console.log(user);

    req.session.regenerate((err) => {
        if(err) next(err);
        req.session.user = {
            name: user.name.split(" ").slice(0,-2).join(" "),
            regNo: user.name.split(" ")[-1],
            email: user.email
        };
        res.redirect('/dashboard');
    });
});

app.get('/dashboard', isAuthenticated, (req,res) => {
    res.send('Hello');
});

app.get('/logout', isAuthenticated, (req,res,next) => {
    req.session.destroy((err) => {
        if(err) next(err);
        res.redirect('/');
    });
});

module.exports = app;