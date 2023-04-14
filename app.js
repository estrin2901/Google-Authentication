
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");  
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose'); 
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express(); 

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended:true
}));


app.use(
    session({
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: false
  }));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");


//Create new mongoose schema

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String
});


// usage plugin passsport-local mongoose

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());    

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secret",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {

    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] }
  
));

app.get("/auth/google/secret", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets page.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
    res.render("login");
});

app.post("/login", function (req, res){
 const user = new User({
    username: req.body.username,
    password: req.body.password
 });

 req.login(user, function(err){
    if(err){
        console.log(err);
    } else {
        passport.authenticate("local")(req, res,function(){
            res.redirect("/secrets");
        });
    }
 });
});


app.get("/register", function(req, res){
    res.render("register");
});


app.get("/secrets", function(req, res){
    if(req.isAuthenticated()){
        console.log("req is Authenticated.");
        res.render("secrets");
    } else {
        console.log("req is not authenticated,");
        res.redirect("/login");
    }
});

app.get("/logout", function(req, res){
    req.logout(function(err){
        if(err){
            return nextTick(err);
        }
        res.redirect("/");
    });
});


app.post("/register", function(req, res){

User.register(
    {username:req.body.username},
    req.body.password,
    function(err, user){
    if(err){
        console.log("ERROR" + err);
        res.redirect("/register");
    } else {
        passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
        });
    }
    }
    );
});





app.listen(3000, function(){
    console.log("Server started on port 3000.");
});