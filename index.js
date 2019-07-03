var express = require("express");
var mongoose = require("mongoose");
var bodyparser = require("body-parser");
var passport = require("passport");
var User = require("./models/User");
var db = require("./mysetup/myurl").myurl;
var bcrypt = require('bcrypt');
const jsonwt = require("jsonwebtoken");

var saltRounds = 10;
var app = express();
var key = require("./mysetup/myurl").secret;
var port = process.env.PORT || 3000;

app.use(bodyparser.urlencoded({ extended: false }));
app.use(bodyparser.json());

mongoose
    .connect(db)
    .then(() => {
        console.log("Database is connected");
    })
    .catch(err => {
        console.log("Error is ", err.message);
    });



app.use(passport.initialize());

require("./strategies/jsonwtStrategy")(passport);

app.get("/", (req, res) => {
    res.status(200).send(`Hi Welcome to the Login and Signup API`);
});

app.post("/signup", async (req, res) => {
    var newUser = new User({
        name: req.body.name,
        password: req.body.password
    });

    await User.findOne({ name: newUser.name })
        .then(async profile => {
            if (!profile) {
                bcrypt.hash(newUser.password, saltRounds, async (err, hash) => {
                    if (err) {
                        console.log("Error is", err.message);
                    } else {
                        newUser.password = hash;
                        await newUser
                            .save()
                            .then(() => {
                                res.status(200).send(newUser);
                            })
                            .catch(err => {
                                console.log("Error is ", err.message);
                            });
                    }
                });
            } else {
                res.send("User already exists...");
            }
        })
        .catch(err => {
            console.log("Error is", err.message);
        });
});

app.post("/login", async (req, res) => {
    var newUser = {};
    newUser.name = req.body.name;
    newUser.password = req.body.password;
  
    await User.findOne({ name: newUser.name })
      .then(profile => {
        if (!profile) {
          res.send("User not exist");
        } else {
          bcrypt.compare(
            newUser.password,
            profile.password,
            async (err, result) => {
              if (err) {
                console.log("Error is", err.message);
              } else if (result == true) {
                //   res.send("User authenticated");
                const payload = {
                  id: profile.id,
                  name: profile.name
                };
                jsonwt.sign(
                  payload,
                  key.secret,
                  { expiresIn: 3600 },
                  (err, token) => {
                    res.json({
                      success: true,
                      token: "Bearer " + token
                    });
                  }
                );
              } else {
                res.send("User Unauthorized Access");
              }
            }
          );
        }
      })
      .catch(err => {
        console.log("Error is ", err.message);
      });
  });
  
  


app.get(
    "/profile",
    passport.authenticate("jwt", { session: false }),
    (req, res) => {
        console.log(req);
        res.json({
            id: req.user.id,
            name: req.user.name
        });
    }
);

app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});