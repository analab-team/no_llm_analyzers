from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers.analyze import monitoring_router
from routers.manager import manager_router

app = FastAPI(title="Sequence Matcher Analyzer")
app.include_router(monitoring_router)
app.include_router(manager_router)

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["api_key"],
)
