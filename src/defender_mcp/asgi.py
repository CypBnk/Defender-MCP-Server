"""ASGI entry point: uvicorn defender_mcp.asgi:app"""
from .app import create_app

app = create_app()
