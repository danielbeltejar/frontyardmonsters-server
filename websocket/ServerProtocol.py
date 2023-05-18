from fastapi import FastAPI, HTTPException, Request, WebSocket, APIRouter

router = APIRouter()


@router.websocket("/")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
        # Handle received data and send back a response
        response = f"You sent: {data}"
        await websocket.send_text(response)
