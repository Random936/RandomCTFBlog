const express = require('express')
const app = express()
const expressFileUpload = require('express-fileupload')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const fs = require('fs')
const jwt = require('jsonwebtoken')
const Datastore = require('nedb')
const bcrypt = require('bcrypt')
const uuid = require('uuid')

// Change before production!
const websitedomain = 'randomctf.com'
const portnumber = 80
const jwtsecret = uuid.v4()
const saltRounds = 10

let db = {}
db.users = new Datastore({ filename: 'users.db', autoload: true })
db.posts = new Datastore({ filename: 'posts.db', autoload: true })
db.tracking = new Datastore({ filename: 'tracking.db', autoload: true })

app.use(express.static('static'))
app.use(expressFileUpload({ safeFileNames: true }))
app.use(cookieParser())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(trackUsers)

app.use(function (req, res, next) {
    console.log(req.method + ' request from ' + req.ip + ' to ' + req.url)
    next()
})

app.set('view engine', 'ejs')
app.set('trust proxy', true)

/*
--------------------------------------------------
                  Main Paths
--------------------------------------------------
*/

app.get('/', (req, res) => {
    res.render('index.ejs')
})

/*
app.get('/member', MemberAuth, (req, res) => {
    res.render('member.ejs')
})
*/

app.get('/admin', AdminAuth, (req, res) => {
    res.render('admin.ejs')
})

/*
--------------------------------------------------
                  Tracking API
--------------------------------------------------
*/

function trackUsers(req, res, next) {

    if (typeof req.url !== "string" || typeof req.headers['user-agent'] !== "string") {
        return next()
    } else if (!req.cookies.logging_token || !uuid.validate(req.cookies.logging_token)) {
        
        let logging_token = uuid.v4()
        let newrecord = {
            token: logging_token,
            firstvisit: Date.now(),
            lastvisit: Date.now(),
            useragent: req.headers['user-agent'],
            paths: [req.url]
        }

        if (typeof req.headers.referer === 'string' && !req.headers.referer.includes(websitedomain)) {
            newrecord.referer = req.headers.referer
        } else {
            newrecord.referer = ''
        }

        db.tracking.insert(newrecord, (err) => {
            if (err) {return next()}
        })

        res.cookie('logging_token', logging_token, {maxAge: 31556926000000})
        return next()

    }

    db.tracking.findOne({ token: req.cookies.logging_token }, (err, record) => {
        if (err) {
            return next()
        } else if (!record) {
            res.clearCookie('logging_token')
            return next()
        }

        if (!record.paths.includes(req.url)) {
            
            db.tracking.update(
                { token: req.cookies.logging_token },
                { $push: { paths: req.url }, $set: { lastvisit: Date.now() }},
                (err) => {
                if (err) {
                    return next()
                } else {
                    console.log("INFO: Added " + req.url + " to paths for the UUID: " + record.token)
                    return next()
                }
            })

        } else {

            db.tracking.update(
                { token: req.cookies.logging_token },
                { $set: { lastvisit: Date.now() }},
                (err) => {
                if (err) {
                    return next()
                } else {
                    return next()
                }
            })
            
        }

    })

}

app.get('/website/loadall', AdminAuth, (req, res) => {
    db.tracking.find({}, (err, records) => {
        if (err || !records) {
            return res.end(JSON.stringify({status: "failed"}))
        } else {
            return res.end(JSON.stringify({
                status: "success",
                records: records
            }))
        }
    })
})

app.get('/website/stats', AdminAuth, (req, res) => {

    let statistics = {}
    db.tracking.find({}, (err, records) => {
        if (err || !records) {return res.end(JSON.stringify({status: "failed"}))}
        
        statistics.totalviews = records.length
        statistics.activeusers = 0
        statistics.newvisits = [0, 0, 0, 0, 0, 0, 0]
        statistics.posts = []
        statistics.postviews = []

        records.forEach((record) => {

            if (record.firstvisit > (Date.now() - 604800000)) {
                let day
                for (day = 0; Date.now() - (86400000 * day) < Date.now(); day++)
                console.log(day)
                statistics.newvisits[day]++
            }

            if (record.lastvisit > Date.now() - 604800000) {
                statistics.activeusers++
            }

            record.paths.forEach((path) => {
                if (!statistics.posts.includes(path) && path.match(/\/posts\/(load\/.+|contact|about)/)) {
                    statistics.posts.push(path)
                    statistics.postviews.push(1)
                } else {
                    let pathindex = statistics.posts.findIndex(pathinarr => pathinarr === path)
                    statistics.postviews[pathindex]++
                }
            })

        })

        statistics.newvisits.reverse()

        res.end(JSON.stringify({
            status: "success",
            statistics: statistics
        }))
    })

})

/*
--------------------------------------------------
              Login Routes & Logic
--------------------------------------------------
*/

app.get('/login', (req, res) => {
    res.render('login.ejs', { loginmessage: "" })
})

app.post('/login', (req, res) => {
    
    console.log("INFO: Login attempt with username: " + req.body.username)

    if (typeof req.body.username !== "string" || typeof req.body.password !== "string") {
        console.log("WARNING: NoSQL injection attempt detected! " + req.socket.address)
        return res.render('login.ejs', { loginmessage: "An unknown error occured." })
    }

    db.users.findOne({ 
        username: req.body.username
    },(err, user) => {

        if (err) {return res.render('login.ejs', { loginmessage: "An unknown error occured." })}

        if (user) {

            if (bcrypt.compareSync(req.body.password, user.password)) {
                const jwtToken = jwt.sign(
                    { username: user.username, isadmin: user.isadmin },
                    jwtsecret
                )
        
                res.cookie("login_token", jwtToken, {maxAge: 2592000000})
    
                if (user.isadmin === true) {
                    console.log("INFO: Admin login successful.")
                    return res.redirect('/admin')
                } else {
                    console.log("INFO: Member login successful.")
                    return res.redirect('/member')
                }

            }

        }

        res.render('login.ejs', { loginmessage: "Invalid username or password." })
    })

})

app.get('/logout', (req, res) => {
    res.clearCookie('login_token')
    res.redirect('/login')
})

/*
--------------------------------------------------
            Sign Up Routes & Logic
--------------------------------------------------
*/

/*
app.get('/signup', (req, res) => {
    res.render('signup.ejs', { signupmessage: "" })
})

app.post('/signup', (req, res) => {

    if (typeof req.body.username !== "string" || typeof req.body.password !== "string") {

        console.log("WARNING: NoSQL injection attempt detected! " + req.socket.address)
        return res.render('signup.ejs', { signupmessage: "An unknown error occured."})

    } else if (req.body.password !== req.body.confpass) {

        return res.render('signup.ejs', { signupmessage: "Passwords did not match."})

    } else if (req.body.username.length <= 0 || req.body.password.length <= 8) {

        return res.render('signup.ejs', { signupmessage: "Password must be at least 8 characters long."})
        
    } 
    
    if (req.body.username.match(/[a-zA-Z0-9]+/)) {
        const username = req.body.username.match(/[a-zA-Z0-9]+/)[0]
        if (username !== req.body.username) {
            return res.redirect('/admin')
        }
    } else {
        return res.redirect('/admin')
    }

    db.users.findOne({username: req.body.username}, (err, user) => {
        if (err || user) {
            return res.render('signup.ejs', { 
                signupmessage: "A user with that username already exists."
            })
        }

        const passwordhash = bcrypt.hashSync(req.body.password, saltRounds)

        db.users.insert({ 
            username: req.body.username,
            password: passwordhash,
            isadmin: false
        },(err) => {
            if (err) {
                return res.render('signup.ejs', { 
                    signupmessage: "An error occured when creating the user."
                })
            }

            console.log("INFO: Successfully created user with username: " + req.body.username)
            res.redirect('/login')

        })

    })

})
*/

/*
--------------------------------------------------
              Authentication Logic
--------------------------------------------------
*/

function UserIsAdmin(login_token) {

    let result
    if (login_token) {
        jwt.verify(login_token, jwtsecret, (err, user) => {
            if (err || user.isadmin !== true) {
                result = false
            } else {
                result = true
            }
        })
    }

    return result
}

function MemberAuth(req, res, next) {

    if (req.cookies.login_token) {
        jwt.verify(req.cookies.login_token, jwtsecret, (err) => {
            if (err) {
                return res.redirect('/login')
            } else {
                next()
            }
        })
    } else {
        return res.redirect('/login')
    } 
}

function AdminAuth(req, res, next) {

    if (req.cookies.login_token) {
        jwt.verify(req.cookies.login_token, jwtsecret, (err, user) => {
            if (err || user.isadmin !== true) {
                return res.redirect('/login')
            } else {
                next()
            }
        })
    } else {
        return res.redirect('/login')
    }
    
}

/*
--------------------------------------------------
                  User API Routes
--------------------------------------------------
*/

app.get('/users/loadall', AdminAuth, (req, res) => {

    db.users.find({}, (err, users) => {

        if (err || !users) {return res.end(JSON.stringify({ status: "failed" }))}

        return res.end(JSON.stringify({
            status: "success",
            users: users
        }))

    })
})

app.get('/users/delete/:username', (req, res) => {

    if (typeof req.params.username !== "string") {
        console.log("WARNING: NoSQL injection attempt detected! " + req.socket.address)
        return res.end(JSON.stringify({ status: 'failed' }))
    }

    if (req.cookies.login_token) {

        jwt.verify(req.cookies.login_token, jwtsecret, (err, user) => {
            if (err || !user) {return res.end(JSON.stringify({ status: 'failed' }))}
    
            if (user.isadmin === true || user.username === req.params.username) {
    
                if (user.username === req.params.username) {
                    res.clearCookie('login_token')
                }
    
                db.users.remove({ username: req.params.username }, {}, (err) => {
                    if (err) {return res.end(JSON.stringify({ status: 'failed' }))}
                    console.log("INFO: Removed user: ", req.params.username)
                    return res.end(JSON.stringify({ status: 'success' }))
                })
    
            }
    
        })

    }
    return res.end(JSON.stringify({ status: 'failed' }))
})

app.get('/users/changerole/:username', AdminAuth, (req, res) => {
    
    if (typeof req.params.username !== "string") {
        console.log("WARNING: NoSQL injection attempt detected! " + req.socket.address)
        return res.end(JSON.stringify({ status: 'failed' }))
    }

    db.users.findOne({ username: req.params.username }, (err, user) => {
        if (err || !user) {return res.end(JSON.stringify({ status: 'failed' }))}
        
        let updateduser = { 
            username: user.username,
            password: user.password,
        }
        if (user.isadmin === false) {
            updateduser.isadmin = true
        } else {
            updateduser.isadmin = false
        }
        
        db.users.update(user, updateduser, {}, (err) => {
            if (err) {return res.end(JSON.stringify({ status: 'failed' }))}
            if (updateduser.isadmin) {
                console.log("INFO: Changed " + user.username + "'s role to admin.")
            } else {
                console.log("INFO: Changed " + user.username + "'s role to member.")
            }
            
        })

        return res.end(JSON.stringify({ status: "success" }))
        
    })

})

app.post('/users/create', AdminAuth, (req, res) => {

    if (typeof req.body.username !== "string" || typeof req.body.password !== "string") {
        console.log("WARNING: NoSQL injection attempt detected! " + req.socket.address)
        return res.redirect('/')
    }

    if (req.body.username.match(/[a-zA-Z0-9]+/)) {
        const username = req.body.username.match(/[a-zA-Z0-9]+/)[0]
        if (username !== req.body.username) {
            return res.redirect('/admin')
        }
    } else {
        return res.redirect('/admin')
    }

    let adminstatus
    if (req.body.isadmin === "on") {
        adminstatus = true
    } else {
        adminstatus = false
    }

    db.users.findOne({ username: req.body.username }, (err, user) => {
        if (err || user) {return res.redirect('/admin')}

        const passwordhash = bcrypt.hashSync(req.body.password, saltRounds)

        db.users.insert({
            username: req.body.username,
            password: passwordhash,
            isadmin: adminstatus
        }, (err) => {
            if (err) {return res.redirect('/admin')}

            console.log("INFO: Successfully created user." + 
            "\tUsername: " + req.body.username +
            "\tAdmin Permissions: " + adminstatus)
            res.redirect('/admin')
        })

    })
    
})

/*
--------------------------------------------------
            Blog API Routes Management
--------------------------------------------------
*/

app.post('/posts/create', AdminAuth, (req, res) => {

    if (req.body.postname.length <= 0 || req.body.postcontent.length <= 0) {
        return res.redirect('/admin')
    }

    let imagename = ""
    if (req.files) {
        imagename = req.files.image.name
        fs.writeFileSync(__dirname + '/static/uploads/' + req.files.image.name + '.jpg', req.files.image.data)
    }

    db.posts.insert({
        type: "private",
        name: req.body.postname,
        image: imagename,
        content: req.body.postcontent,
    }, (err, post) => {
        if (err || !post) {return res.redirect('/admin')}
        console.log("INFO: Created post " + post.name + " with content length " + post.content.length)
        res.redirect('/admin')
    })

})

app.post('/posts/edit/:id', AdminAuth, (req, res) => {
    
    if (typeof req.params.id !== "string") {
        console.log("WARNING: NoSQL injection attempt detected! " + req.socket.address)
        return res.redirect('/admin')
    }

    if (typeof req.body.postname !== "string" || typeof req.body.postcontent !== "string") {
        return res.redirect('/admin')
    }

    db.posts.findOne({ _id: req.params.id }, (err, post) => {
        if (err || !post) {return res.redirect('/admin')}

        let updatedpost = {
            name: req.body.postname,
            content: req.body.postcontent
        }

        if (req.files) {
            
            updatedpost.image = req.files.image.name
            if (fs.existsSync(__dirname + '/static/uploads/' + post.image + '.jpg')) {
                fs.unlinkSync(__dirname + '/static/uploads/' + post.image + '.jpg')
            }

            fs.writeFileSync(__dirname + '/static/uploads/' + req.files.image.name + '.jpg', req.files.image.data)
        }

        db.posts.update({ _id: req.params.id }, { $set: updatedpost }, (err) => {
            if (err) {return res.redirect('/admin')}
        })

    })

    res.redirect('/admin')
})

app.get('/posts/set/:type/:id', AdminAuth, (req, res) => {

    if (typeof req.params.id !== "string" || typeof req.params.type !== "string") {
        console.log("WARNING: NoSQL injection attempt detected! " + req.socket.address)
        return res.end(JSON.stringify({ status: "failed" }))
    }

    if (req.params.type === "contact" || req.params.type === "about") {
        db.posts.update({ type: req.params.type }, { $set: { type: "private" }}, (err) => {
            if (err) {return res.end(JSON.stringify({ status: "failed" }))}
        })
    }

    db.posts.findOne({ _id: req.params.id }, (err, post) => {
        if (err || !post) {return res.end(JSON.stringify({ status: "failed" }))}

        db.posts.update({ _id: req.params.id }, { $set: { type: req.params.type }}, (err) => {
            if (err) {return res.end(JSON.stringify({ status: "failed" }))}

            console.log("INFO: Set " + post.name + " as about page.")
            return res.end(JSON.stringify({ status: "success" }))
        })

    })

})

app.get('/posts/delete/:id', AdminAuth, (req, res) => {

    if (typeof req.params.id !== "string") {
        console.log("WARNING: NoSQL injection attempt detected! " + req.socket.address)
        return res.end(JSON.stringify({ status: "failed" }))
    }

    db.posts.findOne({ _id: req.params.id }, (err, post) => {
        if (err || !post) {return res.end(JSON.stringify({ status: "failed" }))}

        if (post.image !== undefined && fs.existsSync(__dirname + '/static/uploads/' + post.image + '.jpg')) {
            fs.unlinkSync(__dirname + '/static/uploads/' + post.image + '.jpg')
        }

        db.posts.remove({ _id: req.params.id }, {}, (err) => {
            if (err) {return res.end(JSON.stringify({ status: "failed" }))}
            console.log("INFO: Removed the post: " + post.name)
            return res.end(JSON.stringify({ status: "success" }))
        })

    })

    return res.end(JSON.stringify({ status: "failed" }))
})

/*
--------------------------------------------------
              Blog API Routes Querys
--------------------------------------------------
*/

app.get('/posts/about', (req, res) => {

    db.posts.findOne({ type: "about" }, (err, post) => {
        if (err || !post) {return res.end(JSON.stringify({ status: "failed" }))}

        return res.end(JSON.stringify({
            status: "success",
            post: post
        }))

    })

})

app.get('/posts/contact', (req, res) => {

    db.posts.findOne({ type: "contact" }, (err, post) => {
        if (err || !post) {return res.end(JSON.stringify({ status: "failed" }))}

        return res.end(JSON.stringify({
            status: "success",
            post: post
        }))

    })

})

app.get('/posts/load/:id', (req, res) => {
    
    if (typeof req.params.id !== "string") {
        console.log("WARNING: NoSQL injection attempt detected! " + req.socket.address)
        return res.end(JSON.stringify({ status: "failed" }))
    }

    db.posts.findOne({ _id: req.params.id }, (err, post) => {
        if (err || !post) {return res.end(JSON.stringify({ status: "failed" }))}

        if (post.type === "post" || UserIsAdmin(req.cookies.login_token)) {
            return res.end(JSON.stringify({
                status: "success",
                post: post
            }))
        } else {
            return res.end(JSON.stringify({status: "failed"}))
        }

    })

})

app.get('/posts/loadall', (req, res) => {

    db.posts.find({}, (err, posts) => {
        if (err || !posts) {return res.end(JSON.stringify({ status: "failed" }))}

        let returnedposts = []
        if (UserIsAdmin(req.cookies.login_token)) {
            returnedposts = posts
        } else {
            posts.forEach((post) => {
                if (post.type === "post") {
                    returnedposts.push(post)
                }
            })
        }
        
        returnedposts.forEach((post) => {

            post.length = post.content.length
            if (post.content.match(/[^.!?]+[.!?]/g) !== null) {
                post.content = post.content.match(/[^.!?]+[.!?]/g)[0]
            } else {
                post.content = post.content.substring(0, 100)
            }
            
        })
        
        return res.end(JSON.stringify({
            status: "success",
            posts: returnedposts
        }))

    })

})

app.listen(portnumber, () => {
    console.log("Now listening for incoming connections.")
    console.log("JWT Secret set to the UUID: " + jwtsecret)
})