const express = require('express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const jwt = require('jsonwebtoken')
const app = express()
const Datastore = require('nedb')
const db = new Datastore({ filename: 'database.db', autoload: true })

// Change before production!
const jwtsecret = "q3HKVf5TG2ez4KSeBlPXWRWQca3B5FNrPF0BHGPF"

app.use(cookieParser())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.set('view engine', 'ejs')

app.get('/', (req, res) => {
    res.render('index.ejs', { loginmessage: "" })
})

app.post('/login', (req, res) => {
    
    console.log("Username: " + req.body.username + "\tPassword: " + req.body.password)

    if (typeof req.body.username !== "string" || typeof req.body.password !== "string") {
        console.log("WARNING: NoSQL injection attempt detected! " + req.socket.address)
        return res.render('index.ejs', { loginmessage: "An unknown error occured." })
    }

    db.findOne({ 
        username: req.body.username, 
        password: req.body.password
    },(err, user) => {
        if (err) {return undefined}

        if (user) {

            const jwtToken = jwt.sign(
                {username: user.username, isadmin: user.isadmin},
                jwtsecret
            )
    
            res.cookie("login_token", jwtToken, {maxAge: 2592000000})

            if (user.isadmin === true) {
                console.log("Admin login successful.")
                res.redirect('/admin')
            } else {
                console.log("Member login successful.")
                res.redirect('/member')
            }
    
        } else {
            res.render('index.ejs', { loginmessage: "Invalid username or password." })
        }

    })

})

app.get('/logout', (req, res) => {
    res.clearCookie('login_token')
    res.redirect('/')
})

app.get('/signup', (req, res) => {
    res.render('signup.ejs', { signupmessage: "" })
})

app.post('/signup', (req, res) => {

    if (typeof req.body.username !== "string" || typeof req.body.password !== "string") {
        console.log("WARNING: NoSQL injection attempt detected! " + req.socket.address)
        return res.render('signup.ejs', { signupmessage: "An unknown error occured."})
    }
    
    if (req.body.password !== req.body.confpass) {
        return res.render('signup.ejs', { signupmessage: "Passwords did not match."})
    }

    const username = req.body.username.match(/[a-zA-Z0-9]+/)[0]
    if (username !== req.body.username) {
        return res.render('signup.ejs', { signupmessage: "Username is not allowed."})
    }

    db.findOne({username: req.body.username}, (err, user) => {
        if (err || user) {
            return res.render('signup.ejs', { 
                signupmessage: "A user with that username already exists."
            })
        }

        db.insert({ 
            username: req.body.username,
            password: req.body.password,
            isadmin: false
        },(err) => {
            if (err) {
                return res.render('signup.ejs', { 
                    signupmessage: "An error occured when creating the user."
                })
            }

            console.log("Successfully created user." + 
            "\tUsername: " + req.body.username +
            "\tPassword: " + req.body.password)
            res.redirect('/')

        })

    })

})

app.get('/member', MemberAuth, (req, res) => {
    res.render('member.ejs')
})

app.get('/admin', AdminAuth, (req, res) => {
    db.find({}, (err, users) => {
        if (err) {res.end("An error occured")}
        res.render('admin.ejs', { users: users})
    })
})

app.listen(80, () => {console.log("Now listening for incoming connections.")})

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