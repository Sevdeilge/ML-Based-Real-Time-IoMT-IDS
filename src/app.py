from datetime import datetime
from fastapi import FastAPI
import joblib
import pandas as pd
from pydantic import BaseModel
import redis
import json

app = FastAPI()

model = joblib.load("ids_model.pkl")
le = joblib.load("label_encoder.pkl")
features = joblib.load("features.pkl")


class IDSInput(BaseModel):
    Header_Length: float
    Duration: float
    Rate: float
    Srate: float
    fin_flag_number: float
    syn_flag_number: float
    rst_flag_number: float
    psh_flag_number: float
    ack_flag_number: float
    HTTP: float
    HTTPS: float
    DNS: float
    SSH: float
    TCP: float
    UDP: float
    ICMP: float
    IPv: float
    Std: float
    Tot_size: float
    IAT: float
    Number: float


@app.get("/")
def home():
    return {"message": "IDS API çalışıyor"}


@app.post("/predict")
def predict(data: IDSInput):
    input_data = data.model_dump()

    original_feature_order = [
        "Header_Length", "Duration", "Rate", "Srate", "fin_flag_number", 
        "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number", 
        "HTTP", "HTTPS", "DNS", "SSH", "TCP", "UDP", "ICMP", "IPv", "Std", 
        "Tot_size", "IAT", "Number"
    ]

    df = pd.DataFrame([input_data])
    df = df[original_feature_order]

    prediction = model.predict(df)
    label = le.inverse_transform([prediction[0]])

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("logs/attack_logs.txt", "a") as log_file:
        log_file.write(f"{timestamp} | {label[0]}\n")

    return {"prediction": label[0]}