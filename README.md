# oauth-auth-code-flow-pkce
# oauth-auth-code-flow-pkce
## Introduction
This is a NodeJS express application with implements the OAuth 2.0 Authorization Code flow with PKCE.
It was written to work with Okta Customer Identity Cloud but should work with other standards-based implementations.

## Setup
1. Clone or download this repository.
2. Install required packages with `npm install`
3. Copy dotenv.template to .env
4. Edit .env to set discovery URL, logout URL, client_id, and (optional) client_secret.
5. Start the application server with `npm start`
6. Connect to application server at https://localhost:3000
