import importlib.metadata
import os

__version__ = importlib.metadata.version("django-passkey-auth")

template_directory = os.path.join(os.path.dirname(__file__), "templates")
