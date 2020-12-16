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
app.use(bodyParser.urlencoded({extended: true}))
app.use(bodyParser.json())
app.set('view engine', 'ejs')

app.get('/', (req, res) => {
    res.render('index.ejs')
})

app.post('/login', (req, res) => {
    
    console.log("Username: " + req.body.username + "\tPassword: " + req.body.password)

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
            res.redirect('/')
        }

    })

})

app.get('/logout', (req, res) => {
    res.clearCookie('login_token')
    res.redirect('/')
})

app.get('/signup', (req, res) => {
    res.render('signup.ejs', { loginmessage: "" })
})

app.post('/signup', (req, res) => {

    if (req.body.password !== req.body.confpass) {
        res.render('signup.ejs', { loginmessage: "Passwords did not match."})
    }

    db.findOne({username: req.body.username}, (err, user) => {
        if (err || user) {
            res.render('signup.ejs', { 
                loginmessage: "A user with that username already exists."
            })
        }

        db.insert({ 
            username: req.body.username,
            password: req.body.password,
            isadmin: false
        },(err) => {
            if (err) {
                res.render('signup.ejs', { 
                    loginmessage: "An error occured when creating the user."
                })
            }
        })

        console.log("Successfully created user." + 
        "\nUsername: " + req.body.username +
        "\nPassword: " + req.body.password)
        res.redirect('/')
        
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