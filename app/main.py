from fastapi import FastAPI

app = FastAPI(title="RedFlag Antifraud", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/")
def root() -> dict:
    return {"service": "redflag-antifraud", "version": "0.1.0", "docs": "/docs"}
