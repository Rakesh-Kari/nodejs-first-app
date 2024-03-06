import express from 'express';
import path from 'path';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

mongoose
  .connect("mongodb://localhost:27017", {
    dbName: "Backend",
  })
  .then(() => console.log("Database connected"))
  .catch((e) => console.log(e));

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

const User = mongoose.model("User", userSchema);

const app = express();

app.use(express.static(path.join(path.resolve(), "public")));

// Using middlewares
app.use(express.urlencoded({extended:true}));

//Setting up view engine
app.set("view engine","ejs");

const isAuthenicated = async (req,res, next) => {
  const {token} = req.cookies;
  if(token){
    const decoded = jwt.verify(token, "sidubfgwfisu");
    req.user = await User.findById(decoded._id);
    // console.log(decoded);
    next();
  }
  else {
    res.redirect("/login");
  }
}

//Using middleware cookieParser
app.use(cookieParser());

app.get("/", isAuthenicated, (req,res) => {
  // console.log(req.user);
  res.render("logout", {name: req.user.name});
});

app.get("/register",  (req,res) => {
  // console.log(req.user);
  res.render("register");
});

app.get("/login", (req,res) => {
  res.render("login");
})

app.post("/login", async (req,res) => {
  const {email, password} = req.body ;
  const userLogin = await User.findOne({email});

  if(!userLogin) return res.redirect("/register");

  const isMatch = await bcrypt.compare(password, userLogin.password);
  if(!isMatch) return res.render("login", {message:"Incorrect password"});

  const token = jwt.sign({_id: userLogin._id}, "sidubfgwfisu");

  res.cookie("token", token , {
    httpOnly:true, 
    expires:new Date(Date.now() + 60*1000),
  });
  res.redirect("/");

})

app.post("/register", async (req,res) => {
  const {name,email,password} = req.body; //This is the deconstruct method
  // console.log(req.body);
  const userEmail = await User.findOne({email});
  if(userEmail){
    return res.redirect("/login");
  }

  const hashedPassword = await bcrypt.hash(password,10);


  const user = await User.create({
    name,
    email,
    password: hashedPassword,
  });

  const token = jwt.sign({_id: user._id}, "sidubfgwfisu");

  res.cookie("token", token , {
    httpOnly:true, 
    expires:new Date(Date.now() + 60*1000),
  });
  res.redirect("/");
});

app.get("/logout", (req,res) => {
  res.cookie("token", null , {
    httpOnly:true, 
    expires:new Date(Date.now()),
  });
  res.redirect("/");
});




app.listen(5000, () => {
  console.log("Server is working");
});



