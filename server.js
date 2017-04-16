var express = require('express');
var http = require("http");
var https = require("https");
var idContract = require("./contract/id.js");
var services = require("./contract/services.js");
var params = require("./contract/config.json");
var fs = require("fs");
var crypto = require("crypto");

var flat = require('node-flat-db');
var storage = require('node-flat-db/file-sync');
var db = flat('./db/db.json', { storage: storage });
var uuid = require("uuid");

/**
 * Configure ssl keys
 */
//var privateKeyFile = params.PRIVATE_KEY_FILE;
//var certificateFile = params.CERTIFICATE_FILE;

//console.log(privateKeyFile);
//console.log(certificateFile);
//var privateKey  = fs.readFileSync(privateKeyFile, 'utf8');
//var certificate = fs.readFileSync(certificateFile, 'utf8');

//var credentials = {key: privateKey, cert: certificate};

var helmet = require('helmet');

// Create a new Express application.
var app = express();

/**
 * REST Server configuration.
 */
var port = params.port || 8080;
var https_port = params.https_port || 443;
var address = params.address || '0.0.0.0';
var use_https = params.enable_https;

var session = require('express-session');
var FileStore = require('session-file-store')(session);
//app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(session({
   store: new FileStore(),
   secret: 'IDChain7#6g45G', 
   resave: true, 
   saveUninitialized: true    
}));

//Security
app.use(helmet());
app.disable('x-powered-by');

app.use('/login', express.static(__dirname + '/app'));

app.post('/auth', function (req, res) {
  var login = req.body.login;
  var password = req.body.password;
  var auth = false;
  console.log(req.session.login);  
  if (!req.session.login) {
    if( login != void 0 && password != void 0 )
    {
      var user = db('users').find({login: login});
      if (user){        
        //console.log(crypto.createHash('sha256').update(password).digest('base64'));
        auth = user.pwdHash == crypto.createHash('sha256').update(password).digest('base64');
        if (auth){
          req.session.auth = auth;
          req.session.login = login;
          res.end();    
          res.redirect('/testsession');            
        }
      } 
    }
  }  
  if (!auth) {res.redirect('/login');}
});

app.get('/testsession', function(req, res){
  res.setHeader('Content-Type', 'text/html');
    res.write('<p>login: ' + req.session.login + '</p>');
    res.write('<p>auth: ' + req.session.auth + '</p>');
    res.end();
});

function loadUser(req, res, next) {
   console.log('loadUser');
   if (req.session.login) {
    //console.log(req.session.auth);
    //console.log(req.session.login);
      if(req.session.auth === true){
        //console.log(req.session.user);
        next();
      } else {
        res.status(200).json({result: null, error:'Please login!'});
      }    
   } else {
     res.status(200).json({result: null, error:'Please login!'});
   }
}

//Is transaction in block
app.get('/waitTx/:txHash', loadUser,
  function(req, res){

    services.waitTx(req.params.txHash)
    .then(function(result){
      res.status(200).json({result:result, error: null});
    })
    .catch(function(error){
      res.status(500).json({result: null, error: error.message});
    });
});

//Get address of administartion contract
app.get('/address/id/', loadUser, 
  function(req, res){    
    console.log('address/id');
    idContract.address()
    .then(function(result){
      res.status(200).json({result:result, error:null});
    })
    .catch(function(error){
      res.status(500).json({ result: null, error: error.message});
    });
});

//Participant REST API
//Add customer
app.get('/eth/AddHash/token=:token&hash=:hash', loadUser,
  function(req, res){
    idContract.AddHash(req.params.token, req.params.hash)
    .then(function(result){
      res.status(200).json({result:result, error:null});
    })
    .catch(function(error){
      res.status(500).json({ result: null, error: error.message});
    }); 
  });


//Give token permission  
app.get('/eth/GiveTokenPerm/address=:address&token=:token', loadUser,
  function(req, res){
    idContract.GiveTokenPerm(req.params.address, req.params.token)
    .then(function(result){
      res.status(200).json({result:result, error:null});
    })
    .catch(function(error){
      res.status(500).json({ result: null, error: error.message});
    }); 
  });  

//Request by call function 
app.get('/eth/RequestC/token=:token&hash=:hash', loadUser,
  function(req, res){
    idContract.RequestC(req.params.hash, req.params.token)
    .then(function(result){
      res.status(200).json({result:result, error:null});
    })
    .catch(function(error){
      res.status(500).json({ result: null, error: error.message});
    }); 
  });

//Request with transaction sending  
app.get('/eth/Request/hash=:hash&token=:token', loadUser,
  function(req, res){
    idContract.Request(req.params.hash, req.params.token)
    .then(function(result){
      res.status(200).json({result:result, error:null});
    })
    .catch(function(error){
      res.status(500).json({ result: null, error: error.message});
    }); 
  });

//Request with permission control
app.get('/eth/RequestP/token=:token&hash=:hash', loadUser,
  function(req, res){
    idContract.RequestP(req.params.hash, req.params.token)
    .then(function(result){
      res.status(200).json({result:result, error:null});
    })
    .catch(function(error){
      res.status(500).json({ result: null, error: error.message});
    }); 
  });
  
app.get('/teapot',
  function(req,res){
    res.sendStatus(418);
  });

// HTTP server
/*
var http_app = new express();
http_app.all('*', function(req, res){
  res.status(400).send('Use HTTPS protocol instead HTTP.');  
});
*/
var server = http.createServer(app);
server.listen(port, function () {
  console.log('HTTP server listening on port ' + port);
});

// HTTPS server
/*
var httpsServer = https.createServer(credentials, app);
httpsServer.listen(https_port, function(){
	console.log('HTTPS server listening on port ' + https_port );
});
*/