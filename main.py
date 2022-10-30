from fastapi import FastAPI

# run with `uvicorn main:app --reload`
app = FastAPI(docs_url="/")

@app.get("/test")
def read_root():
    return {"Hello": "World"}