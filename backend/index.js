const express = require('express');
const app = express();
const {DBConnection}=require('./database/db.js');
const User=require("./Model/User");
const bcrypt=require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

//configure cors
app.use(cors());

DBConnection();

app.use(express.json());
app.use(express.urlencoded({extended: true}));

app.listen(process.env.PORT,()=>{
    console.log(`Server is running on port ${process.env.PORT}`);
});
app.get('/',(req,res)=>{
    res.send('Hello World');
});

app.post('/register',async (req,res)=>{
    try{
        //get data
        const {firstName,lastName,email,password}=req.body;
        //check data should exist
        if(!(firstName && lastName && email && password)){
            return res.status(400).send("Please enter all the information");
        }
        //check if user already exists
        const existingUser=await User.findOne({email});
        if(existingUser){
            return res.status(400).send("User already exists with the same email address");
        }
        
        //hashing the password
        const hash=bcrypt.hashSync(password,10);
        //save the user in the db
        const user=await User.create({firstName,lastName,email,password:hash});
        //generate a token for user and send it 
        const token=jwt.sign({id: user._id,email},process.env.SECRET_KEY,{expiresIn:'1h'});
        
        user.token=token; //appended by our own
        user.password=undefined; //dont want to share with anyone
        res.status(200).json({message: "User registered successfully",user});

    }catch(error){
        console.log(error);
        res.status(500).send(`Internal Server error`);

    }


});
app.post('/login',async (req,res)=>{
    try{
        //get data
        const {email,password}=req.body;
        //check if details are filled
        if(!(email && password)){
            return res.status(400).send("Please enter all the information");
        }
        //search for existing user
        const existingUser=await User.findOne({email});
        if(!existingUser){
            return res.status(400).send("Invalid email or password");
        }
        //check if password matches
        const matchedPassword=await bcrypt.compare(password,existingUser.password);
        if(!matchedPassword){
            return res.status(400).send("Invalid email or password");
        }
        //generate token
        const token=jwt.sign({id: existingUser._id,email},process.env.SECRET_KEY,{expiresIn:'1h'});
        existingUser.token=token; 
        existingUser.password=undefined;
        res.status(200).json({message: "User logged in successfully",user: existingUser});
    }catch(error){
        console.log("Error while logging in",error);
        res.status(500).send("Internal Server error");
    }
});