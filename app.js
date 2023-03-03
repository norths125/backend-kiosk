var express = require('express')
var cors = require('cors')
var app = express()
var bodyParser = require('body-parser')
var jsonParser = bodyParser.json()
const bcrypt = require('bcrypt');
const saltRounds = 5;
var jwt = require('jsonwebtoken');
const secret ='logintoken';
require('dotenv').config()
app.use(cors())

const mysql = require('mysql2');
// create the connection to database
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME
});
app.post('/register', jsonParser, function (req, res, next) {
  bcrypt.hash(req.body.Password, saltRounds, function(err, hash) {
    connection.execute(
      'INSERT INTO user (User_ID,User_Name,Password,Department,Userlevel) VALUES (?,?,?,?,?)',
      [req.body.User_ID,req.body.User_Name,hash,req.body.Department,req.body.Userlevel],
      function(err, results, fields) {
        if(err){
          res.json({status:'error',message: err})
          return}
        res.json({status:'OK'})
      }
    );
  });
})

app.post('/login', jsonParser, function (req, res, next){
  connection.execute(
    'SELECT * FROM user WHERE User_Name=?',
    [req.body.User_Name],
    function(err, user, fields) {
      if(err) {res.json({status:'error',message: err}); return }
      if(user.length == 0) {res.json({status:'error',message:'no user found'}); return }
      bcrypt.compare(req.body.Password, user[0].Password, function(err, isLogin) {
        if(isLogin){
          var token = jwt.sign({ User_Name:user[0].User_Name ,Userlevel:user[0].Userlevel }, secret, { expiresIn: '1h' });
          if(user[0].Userlevel =='u'){
            res.json({status:'ok',message:'login success',token,userlevel:'u'})
          }else{
            res.json({status:'ok',message:'login success',token,userlevel:'a'})
          }
          
        }else{
          res.json({status:'error',message:'login failed'})
        }
       });
    }
  );
})

app.post('/authen', jsonParser, function (req, res, next){
  try{
    const token = req.headers.authorization.split(' ')[1]
    var decoded = jwt.verify(token, secret);
    res.json({status:'ok',decoded})
  } catch(err){
    res.json({status:'error',message: err.message})
  }
})

app.get('/kiosk', jsonParser, function (req, res, next){
  connection.execute(
    'SELECT * FROM kiosk',
    function(err, kiosk, fields) {
      if(err) {res.json({status:'error',message: err}); return }
      res.json({status:'ok',kiosk})
    }
  );
})

app.put('/kiosk', jsonParser, function (req, res, next){
  connection.execute(
    'SELECT * FROM kiosk',
    function(err, kiosk, fields) {
      if(err) {res.json({status:'error',message: err}); return }
      res.json({status:'ok',kiosk})
    }
  );
})

app.get('/user', jsonParser, function (req, res, next){
  const token = req.headers.authorization.split(' ')[1]
  var decoded = jwt.verify(token, secret);
  console.log(decoded)
  connection.execute(
    'SELECT * FROM user WHERE User_Name=?',
    [decoded.User_Name],
    function(err, user, fields) {
      if(err) {res.json({status:'error',message: err}); return }
      res.json({status:'ok',user})
    }
  );
})





app.listen(process.env.PORT, function () {
  console.log(`CORS-enabled web server listening on port ${process.env.PORT}`)
})