from fastapi import FastAPI

app = FastAPI(
    title="Mock Cyber API",
    description="Simulated cybersecurity product API for connector studies.",
)


@app.get("/health")
def get_health() -> dict[str, str]:
    return {"status": "ok"}
