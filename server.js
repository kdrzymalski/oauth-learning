import express from 'express'
import axios from 'axios'
import session from 'express-session'
import dotenv from 'dotenv'
import { randomBytes } from 'crypto'
import querystring from 'querystring'
import { apiRequest } from './api/apiRequest.js'

dotenv.config()

const app = express()
const port = 7896

app.use(
    session({
        name: 'mySessionCookie',
        secret: process.env.SESSION_SECRET,
        // cookie: {
        //     maxAge: 30000 // czas życia ciastka w milisekundach (30 sekund)
        // },
        resave: false,
        saveUninitialized: true,
    })
)

const githubClientID = process.env.GITHUB_CLIENT_ID
const githubClientSecret = process.env.GITHUB_CLIENT_SECRET
const authorizeURL = 'https://github.com/login/oauth/authorize'
const tokenURL = 'https://github.com/login/oauth/access_token'
const apiURLBase = 'https://api.github.com/'

app.use((req, res, next) => {
    res.locals.baseURL = `https://${req.hostname}${req.originalUrl}`
    next()
})

app.get('/', (req, res) => {
    if (!req.query.action) {
        if (req.session.access_token) {
            res.send(
                '<h3>Logged In</h3><p><a href="/repos">View Repos</a></p><p><a href="?action=logout">Log Out</a></p>'
            )
        } else {
            res.send(
                '<h3>Not logged in</h3><p><a href="?action=login">Log In</a></p>'
            )
        }
    }

    if (req.query.action === 'login') {
        // Usuwanie istniejącego access token z sesji
        req.session.access_token = null

        // Generowanie losowego ciągu i zapisywanie go w sesji
        req.session.state = randomBytes(16).toString('hex')

        const params = {
            response_type: 'code',
            client_id: githubClientID,
            redirect_uri: `http://localhost:7896/callback`,
            scope: 'user public_repo',
            state: req.session.state,
        }

        // Przekierowanie użytkownika do strony autoryzacji GitHub
        const authorizeUrl = `${authorizeURL}?${querystring.stringify(params)}`

        res.redirect(authorizeUrl)
    }
})

app.get('/callback', async (req, res) => {
    // Obsługa powrotu z GitHuba
    if (req.query.code && req.query.state) {
        if (req.query.state !== req.session.state) {
            return res.redirect(`/?error=invalid_state`)
        }
        try {
            const tokenResponse = await apiRequest(
                tokenURL,
                {
                    grant_type: 'authorization_code',
                    client_id: githubClientID,
                    client_secret: githubClientSecret,
                    redirect_uri: `http://localhost:7896/callback`,
                    code: req.query.code,
                },
                {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    Accept: 'application/json',
                }
            )

            if (!tokenResponse || !tokenResponse.access_token) {
                throw new Error('Invalid token response')
            }

            req.session.access_token = tokenResponse.access_token

            res.redirect('/')
        } catch (error) {
            console.error('Error exchanging auth code for token:', error)
            res.redirect(`/?error=token_exchange_failed`)
        }
    } else {
        res.redirect(`/?error=invalid_request`)
    }
})

app.get('/repos', async (req, res) => {
    if (req.session.access_token) {
        const apiUrl = 'https://api.github.com/user/repos'
        const params = {
            sort: 'created',
            direction: 'desc',
        }
        const repos = await apiRequest(
            `${apiUrl}?${querystring.stringify(params)}`,
            null,
            { 'Authorization ': `Bearer ${req.session.access_token}` }
        )

        if (repos) {
            let htmlOutput = '<ul>'
            for (let repo of repos) {
                htmlOutput += `<li><a href="${repo.html_url}">${repo.name}</a></li>`
            }
            htmlOutput += '</ul>'
            res.send(htmlOutput)
        } else {
            res.send('Failed to fetch repositories')
        }
    } else {
        res.redirect('/?error=access_token_missing')
    }
})

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`)
})
