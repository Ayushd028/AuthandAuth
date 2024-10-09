const express = require("express");
const app = express();
const path = require("path");
const cookieParser = require("cookie-parser");
const userModel = require("./models/user");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const user = require("./models/user");

app.set("view engine", "ejs");
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname + "public")));

app.get("/", (req, res) => {
  res.render("index");
});

app.post("/create", (req, res) => {
  let { username, email, password, age, mobile } = req.body;
  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(password, salt, async (err, hash) => {
      let createdUser = await userModel.create({
        username,
        email,
        password: hash,
        age,
        mobile,
      });
      let token = jwt.sign({ email }, "secret");
      res.cookie("token", token);
      res.send("Account Creation Successful");
    });
  });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  // First, find the user by email
  let user = await userModel.findOne({ email: req.body.email });

  if (user) {
    // If user exists, compare the passwords
    bcrypt.compare(req.body.password, user.password, (err, result) => {
      if (result) {
        // If password matches, create a token and set a cookie
        let token = jwt.sign({ email: user.email }, "secret");
        res.cookie("token", token);
        res.send("Login successful");
      } else {
        // If password does not match
        res.send("Email or password is incorrect...");
      }
    });
  } else {
    // If user is not found
    res.send("Email or password is incorrect...");
  }
});

app.get("/logout", (req, res) => {
  res.cookie("token", "");
  res.redirect("/");
});

app.listen(3000, (req, res) => {
  console.log("Listening to Port 3000");
});
