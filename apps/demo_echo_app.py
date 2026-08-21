from __future__ import annotations

import asyncio
import os
from typing import AsyncIterator

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

app = FastAPI(title="Demo Echo App")

APP_ID = os.getenv("CHILD_APP_ID", os.getenv("GATEWAY_APP_ID", "demo-echo"))
MOUNT_PATH = os.getenv("GATEWAY_MOUNT_PATH", "/apps/demo-echo")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "app_id": APP_ID,
        "mount_path": MOUNT_PATH,
    }


@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(
        f"""
        <!doctype html>
        <html>
          <head>
            <meta charset="utf-8" />
            <title>Demo Echo App</title>
          </head>
          <body>
            <h1>Demo Echo App</h1>
            <p>This child app is running behind WebUI Home Gateway.</p>
            <ul>
              <li><a href="./hello">./hello</a></li>
              <li><a href="./stream">./stream</a></li>
            </ul>
            <form method="post" action="./echo">
              <input type="text" name="message" value="hello from form" />
              <button type="submit">POST /echo</button>
            </form>
          </body>
        </html>
        """
    )


@app.get("/hello")
async def hello(request: Request):
    return JSONResponse(
        {
            "message": "hello",
            "app_id": APP_ID,
            "path": str(request.url.path),
            "query": str(request.url.query),
            "headers": {
                "x_forwarded_prefix": request.headers.get("x-forwarded-prefix"),
                "x_forwarded_host": request.headers.get("x-forwarded-host"),
                "x_forwarded_proto": request.headers.get("x-forwarded-proto"),
                "x_gateway_actor_name": request.headers.get("x-gateway-actor-name"),
                "x_gateway_capability": request.headers.get("x-gateway-capability"),
            },
        }
    )


@app.post("/echo")
async def echo(request: Request):
    form = await request.form()
    return {
        "received": dict(form),
        "app_id": APP_ID,
    }


@app.get("/stream")
async def stream():
    async def generate() -> AsyncIterator[bytes]:
        for idx in range(10):
            yield f"data line {idx}\n".encode("utf-8")
            await asyncio.sleep(1)

    return StreamingResponse(generate(), media_type="text/plain; charset=utf-8")


@app.websocket("/ws")
async def websocket_echo(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            message = await websocket.receive_text()
            await websocket.send_text(f"echo:{message}")
    except WebSocketDisconnect:
        return
