'''
This fastapi app provides a test case for ORCID authentication.

The following endpoints are provided:

  /login    Authenticate using ORCID
  /logout   Invalidate credentials
  /         A page that returns an error if not authenticated
  /service  A simple service that returns some scope information for the request

The application defaults to `/protected` for the root path, though this
may be set in the .env file with a `PROTECTED_PATH` property.
'''

import os
import logging
import fastapi.staticfiles
import fastapi.templating
import fastapi.responses
import starlette.config
import starlette.requests
import starlette.middleware.cors
import starlette.middleware.sessions
import starlette.types
import starlette.datastructures
import starlette_oauth2_api
import authlib.integrations.starlette_client

_L = logging.getLogger("protected_app")

# ===================================
class AuthenticateMiddleware(starlette_oauth2_api.AuthenticateMiddleware):
    """
    Override the __call__ method of the AuthenticateMiddleware to also check
    cookies for auth information. This enables access by either a JWT or the
    authentication information stored in a cookie.
    """

    async def __call__(
        self,
        scope: starlette.types.Scope,
        receive: starlette.types.Receive,
        send: starlette.types.Send,
    ) -> None:
        request = starlette.requests.HTTPConnection(scope)
        if request.url.path in self._public_paths:
            return await self._app(scope, receive, send)

        token = None
        user = request.session.get("user")

        # Cookie set with auth info
        if user is not None:
            token = user.get("id_token", None)

        # check for authorization header and token on it.
        elif "authorization" in request.headers and request.headers[
            "authorization"
        ].startswith("Bearer "):
            token = request.headers["authorization"][len("Bearer ") :]

        elif "authorization" in request.headers:
            _L.debug('No "Bearer" in authorization header')
            return await self._prepare_error_response(
                'The "authorization" header must start with "Bearer "',
                400,
                scope,
                receive,
                send,
            )
        else:
            _L.debug("No authorization header")
            return await self._prepare_error_response(
                'The request does not contain an "authorization" header',
                400,
                scope,
                receive,
                send,
            )

        try:
            provider, claims = self.claims(token)
            scope["oauth2-claims"] = claims
            scope["oauth2-provider"] = provider
            scope["oauth2-jwt"] = token
        except starlette_oauth2_api.InvalidToken as e:
            return await self._prepare_error_response(
                e.errors, 401, scope, receive, send
            )

        return await self._app(scope, receive, send)


# Load configuration from the .env file
_L.info("Config file .env exists: %s", os.path.exists(".env"))
config = starlette.config.Config(".env")

app = fastapi.FastAPI(
    debug=True, root_path=config.get("PROTECTED_PATH", default="/protected")
)

app.mount("/static", fastapi.staticfiles.StaticFiles(directory="static"), name="static")
templates = fastapi.templating.Jinja2Templates(directory="templates")

oauth = authlib.integrations.starlette_client.OAuth(config)

app.add_middleware(
    AuthenticateMiddleware,
    providers={
        "orcid": {
            "keys": config.get("ORCID_KEYS", default="https://orcid.org/oauth/jwks"),
            "issuer": config.get("ORCID_ISSUER", default="https://orcid.org"),
            "audience": config.get("ORCID_CLIENT_ID", default="APP-ZTT8BDD9D2LPQNFV"),
        }
    },
    # These paths are not protected, everything else within this app requires authenticated user
    public_paths={
        f"{app.root_path}/login",
        f"{app.root_path}/logout",
        f"{app.root_path}/auth",
    },
)

app.add_middleware(
    starlette.middleware.sessions.SessionMiddleware,
    secret_key=config.get("SECRET_KEY", default="secret-key-not-set"),
)

# https://www.starlette.io/middleware/#corsmiddleware
app.add_middleware(
    starlette.middleware.cors.CORSMiddleware,
    allow_origins=config.get(
        "CORS_ORIGINS",
        cast=starlette.datastructures.CommaSeparatedStrings,
        default=[
            "*",
        ],
    ),
    allow_methods=config.get(
        "CORS_METHODS",
        cast=starlette.datastructures.CommaSeparatedStrings,
        default=["GET", "HEAD"],
    ),
    allow_headers=["authorization"],
)


# Registration here is using openid, which is a higher level wrapper
# around the oauth end points. Take a look at the info at the
# server_metadata_url
oauth.register(
    name="orcid",
    server_metadata_url="https://orcid.org/.well-known/openid-configuration",
    client_kwargs={"scope": "openid"},
    api_base_url="https://orcid.org/",
    ##request_token_url='https://orcid.org/oauth/request_token',
    # access_token_url='https://orcid.org/oauth/token',
    # scope='/authenticate',
    # access_token_params={'grant_type':'authorization_code'},
    # authorize_url='https://orcid.org/oauth/authorize',
    ##authorize_params=None,
)


@app.get("/login")
async def login(request: starlette.requests.Request):
    """
    Initiate OAuth2 login with ORCID
    """
    redirect_uri = request.url_for("auth")
    return await oauth.orcid.authorize_redirect(request, redirect_uri)


@app.get("/auth")
async def auth(request: starlette.requests.Request):
    """
    This method is called back by ORCID oauth. The URL for this method
    needs to be in the registered callbacks of the ORCID Oauth configuration.
    """
    token = await oauth.orcid.authorize_access_token(request)
    request.session["user"] = dict(token)
    return starlette.responses.RedirectResponse(url=request.app.root_path)


@app.get("/logout")
async def logout(request: starlette.requests.Request):
    """
    Logout by removing the cookie from the user session.

    Note that this does not invalidate the JWT, which could continue
    to be used. That's a "feature" of JWTs.

    Basically because a JWT is a static signed document that is
    validated by verifying the signature with a certificate, there
    is no way to invalidate the JWT. It remains valid until it or
    the signing certificate (or a part of the certificate chain)
    expires.
    """
    request.session.pop("user", None)
    return starlette.responses.RedirectResponse(url="/")


@app.get("/service")
async def service(request: starlette.requests.Request):
    """
    This page is not reachable without credentials provided by the
    Bearer token or from a user session cookie.
    """
    data = {
        "claims": request.scope["oauth2-claims"],
        "provider": request.scope["oauth2-provider"],
        "id_token": request.scope["oauth2-jwt"],
    }
    return data


@app.get("/", response_class=fastapi.responses.HTMLResponse)
async def home(request: starlette.requests.Request):
    """
    Show user info or a link to login
    """
    user = request.session.get("user")
    app_info = {
        "root_path": app.root_path,
        "root_path_in_servers": app.root_path_in_servers,
        "servers": app.servers,
        "routes": [route.path for route in app.routes],
    }
    return templates.TemplateResponse(
        "user.html", {"request": request, "user": user, "app_info": app_info}
    )
