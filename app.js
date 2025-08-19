const express = require ('express');
const app  = express();

const userModel = require('./models/userModel');
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const path =  require('path');
const cookieParser = require('cookie-parser');


app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());


app.get('/', (req, res)=>{
    res.render('index');
})

app.post('/create',  (req, res)=>{
    let {username ,email , password ,age} =req.body;

    bcrypt.genSalt(10 , (err, salt)=>{
        bcrypt.hash(password ,salt ,async (err , hash)=>{

            let passwordHashed =hash;
            
            let createdUser = await userModel.create({
                username,
                email,
                password: passwordHashed,
                age
            })

            let token = jwt.sign({email}, "secret");
            res.cookie('token', token);


            res.send(createdUser);
        })
    })


});

app.get('/logout' ,(req, res)=>{
    res.cookie('token',"");
    res.redirect('/');
})

app.get('/login', (req, res)=>{
    res.render('login')
})

app.post('/login', async (req, res)=>{
    let {email, password} = req.body;

    let user = await userModel.findOne({email});
    if(!user) return res.status(404).send("User not found");

        bcrypt.compare(password, user.password, (err, isMatch)=>{
            if(err) return res.status(500).send("Internal Server Error");
            if(!isMatch) return res.status(401).send("Invalid credentials");

            let token = jwt.sign({email}, "secret");
            res.cookie('token', token);
            res.redirect('/');
        })
    })

app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});