"""Gunicorn entry point for the OpenID AIIM sandbox."""

from .live_sandbox import create_app_from_env


_server = create_app_from_env()
app = _server.wsgi
