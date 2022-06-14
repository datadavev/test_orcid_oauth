# Readme for test_auth

This is an evaluation of `authlib` for the purpose of using ORCID to authenticate access to a FastAPI endpoint.

The following OAuth 2.0 roles are used:

- Client: The web browser
- Authorization Server: The ORCID OAuth service
- Resource Server: This FastAPI application
- Resource Owner: The user wit hthe account on ORCID

## Operation

Installing:
```
mkvirtualenv test_auth
poetry install
```

Edit `app/.env` setting:

```
SECRET_KEY={some random string}
ORCID_KEYS=https://orcid.org/oauth/jwks
ORCID_ISSUER=https://orcid.org
ORCID_CLIENT_ID={ORCID Client ID}
ORCID_CLIENT_SECRET={ORCID client secret}
```

The ORCID oauth client settings are at: https://orcid.org/developer-tools

To run:
```
cd app
python main.py
```

Visit http://localhost:8000/

The default page `/` shows information about the user credentials if logged in.

The `/protected` page can be viewed by a browser client if the session cookie 
is set and it contains a valid token, or the client includes the JWT in an
`Authorization: Bearer {JWT}` header.
