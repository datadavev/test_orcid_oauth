"""
This is a pretty rough draft and can likely be streamlined quite a bit.
For example, there's probably no need to use both authlib and
starlette_oauth2_api since there's some overlap of functionality there.
"""

import logging
import logging.config
import fastapi.staticfiles
import fastapi.templating
import fastapi.responses
import starlette.config
import starlette.requests
import starlette.datastructures

# Setup logging before importing other apps that may log on import
LOG_LEVEL: str = "DEBUG"
FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging_config = {
    "version": 1,  # mandatory field
    # if you want to overwrite existing loggers' configs
    # "disable_existing_loggers": False,
    "formatters": {
        "basic": {
            "format": FORMAT,
        }
    },
    "handlers": {
        "console": {
            "formatter": "basic",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
            "level": LOG_LEVEL,
        }
    },
    "loggers": {
        "uvicorn": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
        },
        "protected_app": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
        },
        "test_auth": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            # "propagate": False
        },
        "httpx": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
        },
    },
}
logging.config.dictConfig(logging_config)

# ===================================
# Setup the application

# import the sub-application
import protected_app

_L = logging.getLogger("test_auth")
app = fastapi.FastAPI(debug=True)

# https://fastapi.tiangolo.com/advanced/templates/
app.mount("/static", fastapi.staticfiles.StaticFiles(directory="static"), name="static")
templates = fastapi.templating.Jinja2Templates(directory="templates")

config = starlette.config.Config(".env")

app.mount("/protected", protected_app.app)

# ===================================
# Application endpoints


@app.get("/", response_class=fastapi.responses.HTMLResponse)
async def home(request: starlette.requests.Request):
    """
    Show user info or a link to login
    """
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "protected_path": protected_app.app.root_path},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
