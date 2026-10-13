from fastapi import FastAPI

app = FastAPI(title="CloudGuard AI")

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "cloudguard-api"
    }