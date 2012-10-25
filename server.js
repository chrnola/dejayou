/*
**
**	server.js
**
*/

// Import dependencies
var express = require('express')
  , routes = require('./routes')
  , http = require('http')
  , path = require('path')
  , app = express()
  , sys = require('sys')
  , oauth = require('oauth')
  , sched = require('node-schedule')
  , secrets = require('./secrets');
  
// Now configure the database connection
var Mongolian = require('mongolian')
  , db = new Mongolian(secrets.mongoURI)
  , users = db.collection("users");

// Setup the two OAuth consumers for being able to handle two accounts
// EDIT: This might be unecessary.
function consumer() {
  return new oauth.OAuth(
    "https://api.twitter.com/oauth/request_token", "https://api.twitter.com/oauth/access_token",
    secrets._twitterConsumerKey, secrets._twitterConsumerSecret, "1.0A", secrets.callbackURL, "HMAC-SHA1");
}

function consumerTwo() {
  return new oauth.OAuth(
    "https://api.twitter.com/oauth/request_token", "https://api.twitter.com/oauth/access_token",
    secrets._twitterConsumerKey, secrets._twitterConsumerSecret, "1.0A", secrets.otherCallbackURL, "HMAC-SHA1");
}

// Standard ExpressJS config
app.configure(function(){
  app.set('port', process.env.PORT || 3000);
  app.set('views', __dirname + '/views');
  app.set('view engine', 'jade');
  app.set('title', 'DéjàYou');
  app.use(express.favicon());
  app.use(express.logger('dev'));
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.cookieParser(secrets.cookieSecret));
  app.use(express.session());
  app.use(app.router);
  app.use(express.static(path.join(__dirname, 'public')));
});

app.configure('development', function(){
  app.use(express.errorHandler());
  app.use(function(req, res, next){
    res.locals.session = req.session;
    next();
  })
});

app.get('/', function(req,res){
	if(req.session){
		if(!(req.session.signedIn)){
			//Jade thinks 0 is false
			req.session.signedIn = 0;
		}
	}
	res.render('index.jade', {title: 'DéjàYou', tID: req.session.twitterID, signedIn: req.session.signedIn, user: req.session.twitterScreenName, name: req.session.twitterName, imgURL: req.session.twitterImg, twoauth: req.session.needssecondauth, nameTwo: req.session.twitterNameTwo, userTwo: req.session.twitterScreenNameTwo, imgURLTwo: req.session.twitterImgTwo});
});

app.get('/logout', function(req, res){
  if (req.session) {
        req.session.destroy(function() {
            res.clearCookie('connect.sid', { path: '/' });
			res.redirect('/');
        });
    } else {
        res.send('No session to end.', 500);
    }
});

app.get('/auth', function(req, res){
  consumer().getOAuthRequestToken(function(error, oauthToken, oauthTokenSecret, results){
    if (error) {
      res.send("Error getting OAuth request token : " + sys.inspect(error), 500);
    } else {  
      req.session.oauthRequestToken = oauthToken;
      req.session.oauthRequestTokenSecret = oauthTokenSecret;
	  req.session.signedIn = 0;
      res.redirect("https://api.twitter.com/oauth/authenticate?oauth_token="+req.session.oauthRequestToken);      
    }
  });
});

app.get('/secondauth', function(req, res){
  consumerTwo().getOAuthRequestToken(function(error, oauthToken, oauthTokenSecret, results){
    if (error) {
      res.send("Error getting OAuth request token : " + sys.inspect(error), 500);
    } else {  
      req.session.oauthRequestTokenTwo = oauthToken;
      req.session.oauthRequestTokenSecretTwo = oauthTokenSecret;
	  // Must call the "authorize" endpoint here to force a prompt 
	  // from Twitter so the user can switch accounts
      res.redirect("https://api.twitter.com/oauth/authorize?oauth_token="+req.session.oauthRequestTokenTwo);      
    }
  });
});

app.get('/callback', function(req, res){
  //sys.puts(">>"+req.session.oauthRequestToken);
  //sys.puts(">>"+req.session.oauthRequestTokenSecret);
  //sys.puts(">>"+req.query.oauth_verifier);
  consumer().getOAuthAccessToken(req.session.oauthRequestToken, req.session.oauthRequestTokenSecret, req.query.oauth_verifier, function(error, oauthAccessToken, oauthAccessTokenSecret, results) {
    if (error) {
      res.send("Error getting OAuth access token : " + sys.inspect(error) + "["+oauthAccessToken+"]"+ "["+oauthAccessTokenSecret+"]"+ "["+sys.inspect(results)+"]", 500);
    } else {
      req.session.oauthAccessToken = oauthAccessToken;
      req.session.oauthAccessTokenSecret = oauthAccessTokenSecret;
      // Right here is where we would write out some nice user stuff
      consumer().get("https://api.twitter.com/1.1/account/verify_credentials.json", req.session.oauthAccessToken, req.session.oauthAccessTokenSecret, function (error, data, response) {
        if (error) {
          res.send("So here's the deal: Twitter has this rule that states that you can't try to sign in with your Twitter account more than 15 times in 15 minutes. Either you intentionally just did that, or someone else may be attempting to gain access to your account. Might wanna think about changing your password if you think its easily guessable/brute-forcable.", 500);
        } else {
          var jdata = JSON.parse(data);
		  var u = users.find({"twitterid": jdata["id"]});
		  u.count(function(err, val){
			if(!err){
				if (val < 1){
					//First time user, need to make them a user!
					users.insert({twitterid: jdata["id"]});
					req.session.twitterScreenName = jdata["screen_name"];
					req.session.twitterID = jdata["id"];
					req.session.twitterName = jdata["name"];
					req.session.twitterImg = jdata["profile_image_url"];
					req.session.needssecondauth = 1;
					req.session.signedIn = 1;
					res.redirect('/');
				} else if (val == 1){
					//check for second auth
					var ou = users.find({"twitterid": jdata["id"], "otheraccount": {$exists: true}});
					ou.count(function(err, val){
						if(!err){
							if (val == 1){
                ou.next(function(err, val){
                  if(!err){
                    req.session.needssecondauth = 0;
                    req.session.signedIn = 1;
                    req.session.twitterNameTwo = val.otheraccount.name;
                    req.session.twitterScreenNameTwo = val.otheraccount.screenname;
                    req.session.twitterImgTwo = val.otheraccount.imgURL;
                    req.session.twitterScreenName = jdata["screen_name"];
                    req.session.twitterID = jdata["id"];
                    req.session.twitterName = jdata["name"];
                    req.session.twitterImg = jdata["profile_image_url"];
                    res.redirect('/');
                  } else{
                    res.send(500, "Something weird happened!");
                  }
                });
							} else {
								req.session.needssecondauth = 1;
                //then let them through
                req.session.twitterScreenName = jdata["screen_name"];
                req.session.twitterID = jdata["id"];
                req.session.twitterName = jdata["name"];
                req.session.twitterImg = jdata["profile_image_url"];
                req.session.signedIn = 1;
                res.redirect('/');
							}
						} else{
							res.send(500, "Sorry! Something unexpected happened. Try again? Error Code: A1");
						}
					});
				} else {
					req.session.signedIn = 0;
					sys.puts("UH. Someone has two accounts...");
					res.send(500, "Sorry! Something has gone horribly wrong with your DejaMe account.");
				}
			} else{
				res.send(500, "Sorry! Something unexpected happened. Try again? Error Code: A2");
			}
		  });
        }  
      });  
    }
  });
});

app.get('/callbacktwo', function(req, res){
  consumerTwo().getOAuthAccessToken(req.session.oauthRequestTokenTwo, req.session.oauthRequestTokenSecretTwo, req.query.oauth_verifier, function(error, oauthAccessToken, oauthAccessTokenSecret, results){
    if (error){
      res.send("Error getting OAuth access token : " + sys.inspect(error) + "["+oauthAccessToken+"]"+ "["+oauthAccessTokenSecret+"]"+ "["+sys.inspect(results)+"]", 500);
    } else {
      req.session.oauthAccessTokenTwo = oauthAccessToken;
      req.session.oauthAccessTokenSecretTwo = oauthAccessTokenSecret;
      consumerTwo().get("https://api.twitter.com/1.1/account/verify_credentials.json", req.session.oauthAccessTokenTwo, req.session.oauthAccessTokenSecretTwo, function (error, data, response) {
          if (error) {
            res.send("So here's the deal: Twitter has this rule that states that you can't try to sign in with your Twitter account more than 15 times in 15 minutes. Either you intentionally just did that, or someone else may be attempting to gain access to your account. Might wanna think about changing your password if you think its easily guessable/brute-forcable.", 500);
          } else {
            var jdata = JSON.parse(data);
            // so here i wanna check to make sure that the signed in user
            // doesn't already have a second user associated
            var u = users.find({"twitterid": req.session.twitterID, "otheraccount": {$exists: true}});
            u.count(function(err, val){
              if(!err){
                if (val > 0){
                  res.redirect("/");
                } else {
                  users.update({"twitterid": req.session.twitterID}, {$set: {"otheraccount": {id: jdata["id"], screenname: jdata["screen_name"], imgURL: jdata["profile_image_url"], name: jdata["name"], accessToken: req.session.oauthAccessTokenTwo, oauthAccessTokenSecret: req.session.oauthAccessTokenSecretTwo}}});
                  req.session.needssecondauth = 0;
                  req.session.twitterNameTwo = jdata["name"];
                  req.session.twitterScreenNameTwo = jdata["screen_name"];
                  req.session.twitterImgTwo = jdata["profile_image_url"];
                  res.redirect("/");
                }
              } else{
                res.send(500, "Sorry! Something unexpected happened. Try again? Error Code: A2");
              }
            });
          }
      });
    }
  });
});

http.createServer(app).listen(app.get('port'), function(){
  console.log("DejaYou listening on port " + app.get('port'));
});
