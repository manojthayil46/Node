const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const LocalStrategy = require('passport-local').Strategy;
const cors = require('cors');
var bodyParser = require('body-parser')

const app = express();
app.use(cors());
app.use(bodyParser.json());

// DB Config
const db = require('./config/keys').mongoURI;
const User = require('./models/User');
app.use(passport.initialize());
app.use(passport.session());

// Connect to MongoDB
mongoose
  .connect(
    db,
    { useNewUrlParser: true ,useUnifiedTopology: true}
  )
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log(err));


app.post('/register', (req, res) => {
  const { email, password} = req.body;
  
    User.findOne({ email: email }).then(user => {
      if (user) {
        console.log("user already exists");
        
      } else {
        const newUser = new User({
          email,
          password
        });

        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            newUser.password = hash;
            newUser
              .save()
              .then(user => {
                console.log("registration sucessful");
                res.send({"response" : "registered"});
              })
              .catch(err => console.log(err));
          });
        });
      }
    });
});



passport.use(
  new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
    // Match user
    User.findOne({
      email: email
    }).then(user => {
      if (!user) {
        return done(null, false, { message: 'That email is not registered' });
      }

      // Match password
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) throw err;
        if (isMatch) {
          console.log("login pass");
          return done(null, user);
        } else {
          console.log("login failed");
          return done(null, false, { message: 'Password incorrect' });
        }
      });
    });
  })
);

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


app.post("/login", passport.authenticate("local"), (req, res) => {
  res.send("success");
});


const PORT = process.env.PORT || 5000;

app.listen(PORT, console.log(`Server running on  ${PORT}`));
