// Imports
const express = require('express');
const session = require('express-session');
const qs = require('qs');
const axios = require('axios');
const crypto = require('crypto');

// Load contents of .env into process.env
require('dotenv').config();

// Express setup
const app = express();

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

let port = 3000;
app.listen(port, () => {
  console.log(`Server started.  Listening on port ${port}.`);
})

// Populate config object from .env file
let config = {
  discoveryUrl: process.env.DISCOVERY_URL,
  logoutUrl: process.env.LOGOUT_URL,
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  redirectUri: process.env.APP_URL + "/auth/callback",
  responseType: process.env.RESPONSE_TYPE,
  scope: process.env.SCOPE
};

// Utility function to generate a random string for PKCE verifier and nonces
function randomString(length) {
        const randomCharset = '0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._~';
        let random = '';
        for (let c = 0, cl = randomCharset.length; c < length; ++c) {
            random += randomCharset[Math.floor(Math.random() * cl)];
        }
        return random;
    }

// Initialization function to get URLs from discovery endpoint.
async function getMetadata() {

  let options = {
    method: "GET",
    url: config.discoveryUrl,
    headers: {
      'accept': 'application/json'
    }
  }

  console.log("** Calling discovery URL:",JSON.stringify(options));
  let response = await axios(options);
  config.metadata = response.data
  console.log("** Metadata: " + JSON.stringify(response.data));
  return true;
}

getMetadata();

// Middleware function to require authentication
// If token object found, pass to next function.
// If no token object found, generates OIDC
// authentication request and redirects user
async function authentication_required(req, res, next) {
  if (req.session.token) {
    next()
  } else {
    req.session.target_url = req.url;

    // Get a 100 character random string to be the pkce verifier
    // Store in session for retrieval after authentication completes
    let pkce_rand = randomString(100);
    req.session.pkce_rand = pkce_rand;

    // Create a hash of the PKCE verifier using SHA256.
    // Base64 the result and then convert to Base64url encoding.
    // This is the PKCE code challenge
    pkce_challenge = crypto.createHash('sha256').update(pkce_rand).digest('base64')
        .replaceAll("+","-")
        .replaceAll("/","_")
        .replaceAll("=","");

    await config.metadata;

    try {

      // Generate URL to redirect to authorization endpoint
      let url = config.metadata.authorization_endpoint + "?" +
				qs.stringify({
					client_id: config.clientId,
					redirect_uri: config.redirectUri,
					scope: config.scope,
					response_type: config.responseType,
					state: randomString(16),
					nonce: randomString(16),
          code_challenge: pkce_challenge,
          code_challenge_method: 'S256'
				});
      console.log("** Calling: " + url);
      res.redirect(url);
    } catch (error) {
      res.send(error);
    }
    return;
  }
}

// OIDC redirect route
// user has authenticated, now get the token
app.get('/auth/callback', async (req, res) => {
  try {
    console.log("** Response: " + req.url);

    // POST data for token endpoint includes PKCE code verifier pulled from session.
    let data = {
      grant_type: "authorization_code",
      code: req.query.code,
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      code_verifier: req.session.pkce_rand
    }

    if (config.clientSecret) {
      data.client_secret = config.clientSecret; 
    };

    let options = {
      method: "POST",
      url: config.metadata.token_endpoint,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      data: qs.stringify(data)
    }
    console.log("** Calling token endpoint:",JSON.stringify(options));
    let response = await axios(options);
    let token = response.data;
    console.log("** Response: " + JSON.stringify(token));
    token.expiry = new Date().getTime() + (token.expires_in * 1000);
    req.session.token = token;
    let target_url = req.session.target_url ? req.session.target_url : "/";
    res.redirect(target_url);
    delete req.session.target_url;
  } catch (error) {
    res.send("ERROR: " + error);
  };
});

// Logout route
app.get('/logout', async (req, res) => {
  if (req.session.token) {
    let token = req.session.token;
    if (token.access_token) await revoke(token.access_token);
    if (token.refresh_token) await revoke(token.refresh_token);
    req.session.destroy();
  }
  if (req.query.slo) {
    res.redirect(config.logoutUrl);
  } else {
    res.send("Logged out");
  }
})

// Home route - requires authentication
// Uses userInfo to get user information in JSON format
app.get('/', authentication_required, async (req, res) => {

  let options = {
    method: "GET",
      url: config.metadata.userinfo_endpoint,
    headers: {
      'authorization': 'Bearer ' + req.session.token.access_token,
      'accept': 'application/json'
    }
  }

  console.log("** Calling userInfo:",JSON.stringify(options));
  let response = await axios(options);
  let userInfo = response.data;
  console.log("** Response: " + JSON.stringify(userInfo));

  res.send(`<h1>Welcome ${userInfo.name}</h1>` +
    `<p>Nickname: ${userInfo.nickname}</p>
    <img src="${userInfo.picture}" />`);
});

//Revoke function
async function revoke(token) {

  let data = {
    client_id: config.clientId,
    token: token
  }

  if (config.clientSecret) {
    data.client_secret = config.clientSecret; 
  };

  let options = {
    method: "POST",
    url: config.metadata.revocation_endpoint,
    headers: {
      'content-type': 'application/x-www-form-urlencoded'
    },
    data: qs.stringify(data)
  }

  console.log("** Calling Revoke:",JSON.stringify(options));
  let response = await axios(options);
  console.log("** Status: " + response.status);
}
