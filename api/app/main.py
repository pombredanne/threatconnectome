import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.auth.auth_module import get_auth_module
from app.auth.firebase_auth_module import FirebaseAuthModule
from app.routers import (
    actionlogs,
    actions,
    auth,
    external,
    misptags,
    pteams,
    tags,
    threat,
    topics,
    users,
)
from app.ssvc import deployer_data


def create_app():
    app = FastAPI(title="Threatconnectome")
    origins = [
        "http://localhost:3000",  # dev
        "http://localhost:4173",  # dev: vite preview
        "http://localhost:5173",  # dev: vite dev
        "http://localhost:8080",  # dev
        "http://localhost",  # dev
        "https://threatconnectome.firebase.app",  # prod-alias
        "https://threatconnectome.metemcyber.ntt.com",  # prod
        "https://threatconnectome.web.app",  # prod-alias
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_credentials=True,
        allow_headers=["*"],
        allow_methods=["DELETE", "GET", "OPTION", "POST", "PUT"],
        allow_origin_regex=r"https:\/\/threatconnectome--.+-[0-9a-z]{8}\.(firebaseapp\.com|web\.app)",
        allow_origins=origins,
    )

    # Register routersx
    app.include_router(auth.router)  # place auth on the top for comfortable docs
    app.include_router(actionlogs.router)
    app.include_router(actions.router)
    app.include_router(external.router)
    app.include_router(misptags.router)
    app.include_router(pteams.router)
    app.include_router(tags.router)
    app.include_router(topics.router)
    app.include_router(users.router)
    app.include_router(threat.router)

    # setup auth
    auth_module = FirebaseAuthModule()

    def override_get_auth_module():
        return auth_module

    # Dependency injection as needed
    app.dependency_overrides[get_auth_module] = override_get_auth_module

    return app


app = create_app()

LOGLEVEL = os.environ.get("API_LOGLEVEL", "INFO").upper()
logging.basicConfig(
    level=LOGLEVEL if LOGLEVEL != "" else "INFO",
    format="%(levelname)s - %(asctime)s - %(name)s - %(message)s",
)

try:
    deployer_data.initialize()
except OSError as error:
    raise Exception(f"Cannot open file Deployer.json. detail: {error}")
except (KeyError, TypeError) as error:
    raise Exception(f"File Deployer.json has invalid syntax. detail: {error}")
