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
const { timeStamp } = require('console')

// Change before production!
const websitedomain = 'randomctf.com'
const portnumber = 3000
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

app.get('/', logStartTime, (req, res) => {
    if (/.*([Bb]ot|[Cc]rawler|[Ll]ighthouse).*/.test(req.headers['user-agent'])) {
        db.posts.find({type: { $ne: 'private'} }, (err, posts) => {
            if (err || !posts) {
                return res.end('An error occured.')
            } else {

                posts.forEach((post) => {
                    if (post.content.match(/[^.!?]+[.!?]/g) !== null) {
                        post.desc = post.content.match(/[^.!?]+[.!?]/g)[0]
                    } else {
                        post.desc = post.content.substring(0, 100)
                    }
                })

                let contactpost = posts.find(post => post.type === 'contact')
                let aboutpost = posts.find(post => post.type === 'about')

                res.render('nojsindex.ejs', {
                    title: 'RandomCTF | Ethical hacking, Programming, and Tutorials',
                    posts: posts,
                    contactid: contactpost._id,
                    aboutid: aboutpost._id,
                    opacity: 0
                })
            }
        })
    } else {
        res.sendFile(__dirname + '/views/index.html')
    }
})

app.get('/post/:id', logStartTime, (req, res) => {
   
    if (/.*([Bb]ot|[Cc]rawler|[Ll]ighthouse).*/.test(req.headers['user-agent'])) {

        if (typeof req.params.id !== 'string') {
            return res.redirect('/')
        }

        db.posts.find({ type: { $ne: 'private' } }, (err, posts) => {
            if (err || !posts) {
                return res.redirect('/')
            }

            posts.forEach((post) => {
                if (post.content.match(/[^.!?]+[.!?]/g) !== null) {
                    post.desc = post.content.match(/[^.!?]+[.!?]/g)[0]
                } else {
                    post.desc = post.content.substring(0, 100)
                }
            })

            let currentpost = posts.find(post => post._id === req.params.id)
            let contactpost = posts.find(post => post.type === 'contact')
            let aboutpost = posts.find(post => post.type === 'about')

            if (currentpost) {
                return res.render('nojsindex.ejs', {
                    title: currentpost.name,
                    posts: posts,
                    currentpost: currentpost,
                    contactid: contactpost._id,
                    aboutid: aboutpost._id,
                    opacity: 1
                })
            }
            
        })

    } else {
        res.sendFile(__dirname + '/views/index.html')
    }

})

app.get('/admin', logStartTime,  AdminAuth, (req, res) => {
    res.sendFile(__dirname + '/views/admin.html')
})

/*
--------------------------------------------------
                  Tracking API
--------------------------------------------------
*/

function trackUsers(req, res, next) {

    if (typeof req.url !== "string" || typeof req.headers['user-agent'] !== "string" || typeof req.ip !== "string") {
        return next()
    } else if (!req.cookies.logging_token || !uuid.validate(req.cookies.logging_token)) {

        let logging_token = uuid.v4()
        let newrecord = {
            token: logging_token,
            user: false,
            firstvisit: Date.now(),
            lastvisit: Date.now(),
            ip: req.ip,
            useragent: req.headers['user-agent'],
            paths: [req.url],
            timestamps: []
        }

        newrecord.referer = ''
        if (typeof req.headers.referer === 'string' && !req.headers.referer.includes(websitedomain)) {
            newrecord.referer = req.headers.referer
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
                { $push: { paths: req.url }, $set: { lastvisit: Date.now(), user: true } },
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
                { $set: { lastvisit: Date.now() } },
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

function logStartTime(req, res, next) {

    if (typeof req.cookies.logging_token !== "string" || typeof req.url !== "string") {
        return next()
    }
    
    db.tracking.update({ token: req.cookies.logging_token }, { $push: {
        timestamps: {
            path: req.url,
            timespent: 0,
            starttime: Date.now(),
            endtime: Date.now()
        } 
    }}, () => {
        return next()
    })
}

app.get('/website/logendtime', (req, res) => {
    
    if (typeof req.cookies.logging_token !== "string" || typeof req.query.path !== "string") {
        return res.end(JSON.stringify({status: "failed"}))
    }

    db.tracking.findOne({ token: req.cookies.logging_token }, (err, record) => {
        if (err || !record) {return res.end(JSON.stringify({status: "failed"}))}

        console.log(req.query.path)
        let timestampindex = record.timestamps.findIndex(
            timestamp => timestamp.path === req.query.path && timestamp.timespent < 1000
        )

        if (timestampindex !== -1) {
            record.timestamps[timestampindex].endtime = Date.now()
            record.timestamps[timestampindex].timespent = record.timestamps[timestampindex].endtime - record.timestamps[timestampindex].starttime
        }

        console.log(record.timestamps)

        db.tracking.update({ token: req.cookies.logging_token }, record, (err) => {
            if (err) {
                return res.end(JSON.stringify({status: "failed"}))
            } else {
                return res.end(JSON.stringify({status: "success"}))
            }
        })

    })

})

app.get('/website/stats', AdminAuth, (req, res) => {

    let statistics = {}
    db.tracking.find({}, (err, records) => {
        if (err || !records) {return res.end(JSON.stringify({status: "failed"}))}
        
        statistics.totalviews = records.length
        statistics.userviews = 0
        statistics.activeusers = 0
        statistics.newvisits = [0, 0, 0, 0, 0, 0, 0]
        statistics.posts = []
        statistics.postviews = []

        records.forEach((record) => {

            if (record.user) {
                statistics.userviews++

                if (record.firstvisit > (Date.now() - 604800000)) {
                    let day
                    for (day = 0; record.firstvisit < Date.now() - (86400000 * day); day++) {}
                    statistics.newvisits[day - 1]++
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
            
            }

        })

        statistics.newvisits.reverse()

        res.end(JSON.stringify({
            status: "success",
            statistics: statistics
        }))
    })

})

app.get('/website/load/:selector', AdminAuth, (req, res) => {

    if (typeof req.params.selector !== "string") {
        return res.end(JSON.stringify({status: "failed"}))
    }

    let query
    if (uuid.validate(req.params.selector)) {
        query = { token: req.params.selector }
    } else {
        switch (req.params.selector) {
            case "all":
                query = {}
                break
            case "bots":
                query = { user: false }
                break
            case "users":
                query = { user: true }
                break
            default:
                return res.end(JSON.stringify({status: "failed"}))
        }
    }   

    db.tracking.find(query, (err, records) => {
        if (err || !records) {return res.end(JSON.stringify({status: "failed"}))}
            
        return res.end(JSON.stringify({
            status: "success",
            records: records
        }))
    })
})

app.get('/website/deletebots', AdminAuth, (req, res) => {
    db.tracking.remove({ user: false }, { multi: true }, (err, removed) => {
        if (err) {
            return res.end(JSON.stringify({status: "failed"}))
        } else {
            console.log("INFO: Removed " + removed + " suspected bot token entries.")
            return res.end(JSON.stringify({status: "success"}))
        }
    })
})

app.get('/website/delete/:token', AdminAuth, (req, res) => {
    if (typeof req.params.token !== "string") {
        return res.end(JSON.stringify({status: "failed"}))
    }

    db.tracking.remove({ token: req.params.token }, (err) => {
        if (err) {
            return res.end(JSON.stringify({status: "failed"}))
        } else {
            
            return res.end(JSON.stringify({status: "success"}))
        }

    })

})

/*
--------------------------------------------------
              Login Routes & Logic
--------------------------------------------------
*/

app.get('/login', logStartTime, (req, res) => {
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

app.post('/posts/upload', AdminAuth, (req, res) => {

    if (req.files) {

        if (req.files.image.mimetype === 'image/jpeg') {
            let imagename = req.files.image.name.slice(0, -3)
            if (imagename.length > 0) {
                fs.writeFileSync(__dirname + '/static/uploads/' + imagename + '.jpg', req.files.image.data)
            }
        }

        return res.redirect('/admin')
    } else {
        res.redirect('/admin')
    }
})

app.post('/posts/create', AdminAuth, (req, res) => {

    if (typeof req.body.postname !== 'string' || typeof req.body.postcontent !== 'string') {
        return res.redirect('/admin')
    }

    if (req.body.postname.length <= 0 || req.body.postcontent.length <= 0) {
        return res.redirect('/admin')
    }

    let imagename = ""
    if (req.files) {

        if (typeof req.files.image.name !== 'string') {
            return res.redirect('admin')
        }
        
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
    
    if (typeof req.params.id !== "string" || typeof req.body.postname !== "string" || typeof req.body.postcontent !== "string") {
        console.log("WARNING: NoSQL injection attempt detected! " + req.socket.address)
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

})

/*
--------------------------------------------------
              Blog API Routes Querys
--------------------------------------------------
*/

app.get('/posts/about', logStartTime, (req, res) => {

    db.posts.findOne({ type: "about" }, (err, post) => {
        if (err || !post) {return res.end(JSON.stringify({ status: "failed" }))}

        return res.end(JSON.stringify({
            status: "success",
            post: post
        }))

    })

})

app.get('/posts/contact', logStartTime, (req, res) => {

    db.posts.findOne({ type: "contact" }, (err, post) => {
        if (err || !post) {return res.end(JSON.stringify({ status: "failed" }))}

        return res.end(JSON.stringify({
            status: "success",
            post: post
        }))

    })

})

app.get('/posts/load/:id', logStartTime, (req, res) => {
    
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