from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import threading

from app.database import Base, engine
from app.routers import alerts, response
from app.websocket_manager import manager
from app.kafka_consumer import start_kafka_consumer

# Create DB tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Network Threat Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router)
app.include_router(response.router)

@app.on_event("startup")
async def startup_event():
    """Start Kafka consumer in background thread on startup"""
    loop = asyncio.get_event_loop()
    thread = threading.Thread(
        target=start_kafka_consumer,
        args=(loop,),
        daemon=True
    )
    thread.start()
    print("🚀 Backend started! Kafka consumer running in background.")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep connection alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/health")
def health():
    return {"status": "ok", "service": "Network Threat Detection API"}
