require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const { ObjectId } = require('mongodb');
const saltRounds = 6;

const app = express();

const Joi = require("joi");


const port = process.env.PORT || 3000;

const expireTime = 60 * 60 * 1000; //expires after 1 hour  ( minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
	collectionName: 'session',
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false, 
	resave: true
}
));


// function for session validation 
function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

// Redirect to login index if not logged in
function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/indexl');
    }
}

function isAdmin(req) {
    return req.session.user_type === 'admin';
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.render('error', {
            errorMessage: 'You do not have permission to access this page.',
        });
    } else {
        next();
    }
}


function generateNavigationHTML(isAuthenticated, userType, currentRoute) {
    let navHTML = `
    <div class="container">
        <header class="d-flex justify-content-center py-3">
            <ul class="nav nav-pills">`;

    if (!isAuthenticated) {
        navHTML += `<li class="nav-item"><a href="/indexl" class="nav-link${currentRoute === '/indexl' ? ' active' : ''}" aria-current="page">Home</a></li>`;
    } else {
        navHTML += `
            <li class="nav-item"><a href="/" class="nav-link${currentRoute === '/' ? ' active' : ''}" aria-current="page">Home</a></li>
            <li class="nav-item"><a href="/members" class="nav-link${currentRoute === '/members' ? ' active' : ''}">Members Area</a></li>`;

        if (userType === 'admin') {
            navHTML += `<li class="nav-item"><a href="/admin" class="nav-link${currentRoute === '/admin' ? ' active' : ''}">Admin</a></li>`;
        }

        navHTML += `<li class="nav-item"><a href="/logout" class="nav-link">Logout</a></li>`;
    }

    navHTML += `
            </ul>
        </header>
    </div>`;

    return navHTML;
}

function generateNavigationMiddleware(req, res, next) {
    const isAuthenticated = req.session.authenticated;
    const userType = req.session.user_type;
    const currentRoute = req.path;
    
    res.locals.navHTML = generateNavigationHTML(isAuthenticated, userType, currentRoute);
    next();
}


app.use(generateNavigationMiddleware);

//homepage if logged in
app.get('/', (req, res) => {
    if (req.session.authenticated) {
        res.render("index", { name: req.session.name });
    } else {
        res.render("indexl");
    }
});


app.get('/indexl', (req, res) => {
    res.render('indexl');
});
 

//login
app.get('/login', (req, res) => {
	const showError = req.query.error === '1';
	res.render('login', { showError: showError });
});
  
app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().email().required();
	const validationResult = schema.validate(email);
	
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, password: 1, name: 1, _id: 1, user_type: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		// console.log("user not found");
		res.redirect('/login?error=1');
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		// console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
		req.session.name = result[0].name;
		req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;
		console.log("Session info:", req.session);

		res.redirect('/members');
		return;
	}
	else {
		// console.log("incorrect password");
		res.redirect('/login?error=1');
		return;
	}
});


// User signup added verfication for empty fields
app.get('/signup', (req,res) => {
	res.render("signup");
});

//JOI check

app.post('/submitUser', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;
	var name = req.body.name;

	const schema = Joi.object(
	{
		email: Joi.string().email().required(),
		password: Joi.string().max(20).required(),
		name: Joi.string().alphanum().max(20).required()
	});
	

	const validationResult = schema.validate({email, password, name}, {abortEarly: false});
	if (validationResult.error != null) {
		const errors = validationResult.error.details.map(detail => detail.message);
		const errorMsg = errors.join('<br>');
		res.render('signup-error', { errorMsg: errorMsg });
		return;
	}
	

	var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({email: email, password: hashedPassword, name: name, user_type: "user"});
	console.log("Inserted user");

	req.session.authenticated = true;
	req.session.name = name;
	req.session.cookie.maxAge = expireTime;

	res.redirect('/members');
});

//logout
app.get('/logout', (req,res) => {
	req.session.destroy();
	res.render('logout');
});

// Members page
app.get('/members', sessionValidation, (req, res) => {
	res.render('members', { name: req.session.name });
});

// Admin page  
app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({email: 1, user_type: 1, _id: 1, name: 1}).toArray();
    res.render("admin", {users: result});
});


app.get('/promote/:userId', sessionValidation, adminAuthorization, async (req, res) => {
    const userId = req.params.userId;
    await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: 'admin' } });
    res.redirect('/admin');
});
  
app.get('/demote/:userId', sessionValidation, adminAuthorization, async (req, res) => {
    const userId = req.params.userId;
    await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: 'user' } });
    res.redirect('/admin');
});

app.use(express.static(__dirname + "/public"));

// 404
app.get("*", (req,res) => {
	res.status(404);
	res.render('404');
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 