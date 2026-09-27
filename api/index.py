import os
import sys

# Ensure root directory is in sys.path for Vercel Serverless Function import
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app as flask_app

class VercelPathFixMiddleware:
    """WSGI middleware to normalize PATH_INFO for Vercel Serverless Function rewrites."""
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        path_info = environ.get('PATH_INFO', '')
        if path_info.startswith('/api/index'):
            environ['PATH_INFO'] = path_info[len('/api/index'):] or '/'
        return self.app(environ, start_response)

app = VercelPathFixMiddleware(flask_app)
