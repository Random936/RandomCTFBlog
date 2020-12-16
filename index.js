const express = require('express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const jwt = require('jsonwebtoken')
const app = express()

// Change before production!
const jwtsecret = "q3HKVf5TG2ez4KSeBlPXWRWQca3B5FNrPF0BHGPF"

const users = [{
    username: "administrator",
    password: "password123",
    isadmin: true
},{
    username: "member",
    password: "secret123",
    isadmin: false
}]

app.use(cookieParser())
app.use(bodyParser.urlencoded({extended: true}))
app.use(bodyParser.json())
app.set('view engine', 'ejs')

app.get('/', (req, res) => {
    res.render('index.ejs')
})

app.post('/login', (req, res) => {
    console.log("Username: " + req.body.username);
    console.log("Password: " + req.body.password)
    const user = users.find((user) => {
        return user.username === req.body.username && user.password === req.body.password
    })

    if (user) {
        const jwtToken = jwt.sign(
            {username: user.username, isadmin: user.isadmin},
            jwtsecret
        )

        res.cookie("login_token", jwtToken, {maxAge: 2592000000})
        if (user.isadmin === true) {
            res.redirect('/admin')
        } else {
            res.redirect('/member')
        }

    } else {
        res.redirect('/')
    }
})

app.get('/member', MemberAuth, (req, res) => {
    res.end("Member Page!")
})

app.get('/admin', AdminAuth, (req, res) => {
    res.end("Admin Page!")
})

app.listen(80, () => {})

function MemberAuth(req, res, next) {
    if (req.cookies.login_token) {
        jwt.verify(req.cookies.login_token, jwtsecret, (err) => {
            if (err) {
                return res.sendStatus(403)
            } else {
                next()
            }
        })
    } else {
        return res.sendStatus(401)
    }
}

function AdminAuth(req, res, next) {
    if (req.cookies.login_token) {
        jwt.verify(req.cookies.login_token, jwtsecret, (err, user) => {
            if (err || !user.isadmin === true) {
                return res.sendStatus(403)
            } else {
                next()
            }
        })
    } else {
        return res.sendStatus(401)
    }
}