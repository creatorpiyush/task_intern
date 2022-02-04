require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const cookieParser = require("cookie-parser");

app.use(cookieParser());

const User = require("./model/user");

const auth = require("./middleware/auth");

app.use(express.static(__dirname + "/public"));

app.set("view engine", "hbs");
app.set("views", "./public/views");

app.get("/", (req, res) => {
  res.status(200).render("index");
});

// Register
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  try {
    const { name, email, phone, password, confirm_password } = req.body;

    if (!(email && password && name && phone && confirm_password)) {
      res.status(400).send("All input is required");
    }

    if (password !== confirm_password) {
      res.status(400).send("Password and Confirm Password must match");
    }

    if (password.length < 10) {
      res.status(400).send("Password must be at least 10 characters long");
    }

    const oldUser = await User.findOne({ email });

    if (oldUser) {
      return res.status(409).send("User Already Exist. Please Login");
    }

    let encryptedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      phone,
      email: email.toLowerCase(),
      password: encryptedPassword,
    });

    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY,
      {
        expiresIn: "2d",
      }
    );
    user.token = token;

    res.status(201).redirect("/login");
  } catch (err) {
    console.log(err);
  }
});

// Login

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!(email && password)) {
      res.status(400).send("All input is required");
    }
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: "2d",
        }
      );

      user.token = token;

      res.cookie("x-access-token", token);
      return res.status(200).redirect(`/allData`);
    } else {
      return res.status(400).send("Invalid Credentials");
    }
  } catch (err) {
    console.log(err);
  }
});

app.get("/allData", auth, async (req, res) => {
  try {
    const user = await User.find();
    res.status(200).render("all_data", { user });
  } catch (err) {
    console.log(err);
  }
});

const port = process.env.PORT;

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
