import express from 'express';
import axios from 'axios';
import session from 'express-session';
import dotenv from 'dotenv';
import { randomBytes } from 'crypto';
import querystring from 'querystring';

dotenv.config();


const app = express();
const port = 7896;

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));

const githubClientID = process.env.GITHUB_CLIENT_ID;
const githubClientSecret = process.env.GITHUB_CLIENT_SECRET;
const authorizeURL = 'https://github.com/login/oauth/authorize';
const tokenURL = 'https://github.com/login/oauth/access_token';
const apiURLBase = 'https://api.github.com/';

app.use((req, res, next) => {
    res.locals.baseURL = `https://${req.hostname}${req.originalUrl}`;
    console.log(`https://${req.hostname}${req.originalUrl}`)
    next();
});

app.get('/', (req, res) => {
    if (!req.query.action) {
        if (req.session.access_token) {
            res.send('<h3>Logged In</h3><p><a href="?action=repos">View Repos</a></p><p><a href="?action=logout">Log Out</a></p>');
        } else {
            res.send('<h3>Not logged in</h3><p><a href="?action=login">Log In</a></p>');
        }
    }

    if (req.query.action === 'login') {
        // Usuwanie istniejącego access token z sesji
        req.session.access_token = null;

        // Generowanie losowego ciągu i zapisywanie go w sesji
        req.session.state = randomBytes(16).toString('hex');

        const params = {
            response_type: 'code',
            client_id: githubClientID,
            // na potrzeby testu niech to będzie http://localhost:7896/callback
            redirect_uri: `https://${req.hostname}${req.path}`,
            scope: 'user public_repo',
            state: req.session.state
        };

        // Przekierowanie użytkownika do strony autoryzacji GitHub
        const authorizeUrl = `${authorizeURL}?${querystring.stringify(params)}`;
        res.redirect(authorizeUrl);
    }
});

app.get('/callback', async (req, res) => {
    // Obsługa powrotu z GitHuba
    if (req.query.code && req.query.state) {
        if (req.query.state !== req.session.state) {
            return res.redirect(`/?error=invalid_state`);
        }
        try {
            const tokenResponse = await axios.post(process.env.GITHUB_TOKEN_URL, querystring.stringify({
                grant_type: 'authorization_code',
                client_id: process.env.GITHUB_CLIENT_ID,
                client_secret: process.env.GITHUB_CLIENT_SECRET,
                redirect_uri: `https://${req.hostname}/callback`,
                code: req.query.code
            }), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            });
            req.session.access_token = tokenResponse.data.access_token;
            res.redirect('/');
        } catch (error) {
            console.error('Error exchanging auth code for token:', error);
            res.redirect(`/?error=token_exchange_failed`);
        }
    } else {
        res.redirect(`/?error=invalid_request`);
    }
});

function apiRequest(url, post = null, headers = []) {
    headers.push(
        'Accept: application/vnd.github.v3+json, application/json',
        'User-Agent: https://example-app.com/'
    );

    if (req.session.access_token) {
        headers.push(`Authorization: Bearer ${req.session.access_token}`);
    }

    const config = {
        headers: headers,
        method: post ? 'POST' : 'GET',
        url: url,
    };

    if (post) {
        config.data = post;
    }

    return axios(config).then(response => response.data);
}

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
