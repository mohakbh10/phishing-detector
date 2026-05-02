from fastapi import FastAPI
from pydantic import BaseModel

# import your function
from url_analysis import analyze_email_api

app = FastAPI()

class EmailRequest(BaseModel):
    email_text: str

@app.post("/analyze")
def analyze(data: EmailRequest):
    result = analyze_email_api(data.email_text)
    return result

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow all for now
    allow_credentials=True,
    allow_methods=["*"],  # THIS FIXES OPTIONS
    allow_headers=["*"],
)