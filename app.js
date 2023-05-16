
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");  
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose'); 
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require("mongoose-findorcreate");
const flash = require("connect-flash");



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

 

  // Le digo a la app que use passport y lo inicializamos
app.use(passport.initialize());

// Le digo que use passport para administar la sesiones
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");


//Create new mongoose schema
const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: Array
});


//  uso plugin passsport-local-mongoose en mi userSchema  y es lo que
//  vamos a usar para hash y salt. También servirá para guardar nuestros usuario 
//  en nuestra base de datos de Mongo DB
 
userSchema.plugin(passportLocalMongoose);

userSchema.plugin(findOrCreate);


const User = new mongoose.model("User", userSchema);


//Creo una estrategia local para autenticar (log in) a los usuarios con usuario y contraseña
passport.use(User.createStrategy());    


//Serializo y des-serializo a los usuarios (solo es necesario cuando utilizo sesiones)
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


passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FB,
    clientSecret: process.env.CLIENT_SECRET_FB,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {

    console.log(profile);

    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
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

app.get("/auth/facebook",
  passport.authenticate('facebook', { scope: ["email"] }
  
));

app.get("/auth/google/secret", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets page.
    res.redirect("/secrets");
  });

app.get("/auth/facebook/secrets", 
  passport.authenticate("facebook", { failureRedirect: "/login" }),
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


 //Metodo de passport
 req.login(user, function(err){  //user comes from login credentials 
    if(err){
        console.log(err);  //ERROR if we didn´t find that user in our data base.
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





app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        console.log("req is Authenticated.");
        res.render("submit");
    } else {
        console.log("req is not authenticated,");
        res.redirect("/login");
    }
});

app.post("/submit", function(req,res){
 const submittedSecret = req.body.secret;

 console.log(req.user);

 User.findOneAndUpdate({_id: req.user.id}, {$push: {secret: submittedSecret}})
 .then(()=>{
            res.redirect("/secrets");
        })
 .catch((err)=>{
            console.log(err);
        })
    });


app.get("/logout", function(req, res, next){
    req.logout(function(err){
        if(err){
            return next(err);
        }
        res.redirect("/");
    });
});


app.post("/register", function(req, res){
// Prueba codigo

const passw1 = req.body.password
const passw2 = req.body.confirmpassword

if (passw1 === passw2){

  User.register(
    {username:req.body.username}, //JS Object // Esto viene de passport-local.mongoose
    req.body.password,
    function(err, user){
    if(err){
        console.log("ERROR" + err);
        res.redirect("/register"); //si algo no esta bien redirige a la página de registro.
    } else {
        passport.authenticate("local")(req, res, function(){ //El callback solo se activa si la autenticación fué exitosa y le administramos la cookie para guardar su actual inicio de sesión.
            res.redirect("/secrets");
        });
    }
    }
    );

} else {  
  console.log("Las constraseñas no coinciden");
        res.redirect("/register");
}
});


app.get("/secrets", function(req, res){
    User.find({"secret": {$ne: null}})
    .then(userWithSecrets => {
        res.render("secrets", { secretsToShow: userWithSecrets});
    })
    .catch(err=>{
        console.log(err);
    })
});




app.listen(3000, function(){
    console.log("Server started on port 3000.");
});