import subprocess
from feature_engine import FeatureBuilder
import requests

interface = r"\Device\NPF_{DC1DC608-7452-4AD2-B611-F3466ED1FCA3}"

builder = FeatureBuilder()
cmd = [
    r"C:\Program Files\Wireshark\tshark.exe",
    "-i", interface,
    "-T", "fields",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "frame.len",
    "-e", "ip.proto",          
    "-e", "tcp.flags.fin",
    "-e", "tcp.flags.syn",
    "-e", "tcp.flags.reset",
    "-e", "tcp.flags.push",
    "-e", "tcp.flags.ack"
]

process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

print("IDS running (Sayısal Mod)...\n")

for line in process.stdout:
    try:
        parts = [p.strip() for p in line.split("\t")]

        if len(parts) < 4 or not parts[2]: 
            continue

        while len(parts) < 9:
            parts.append("0")

        src, dst, length, ip_proto, fin, syn, rst, psh, ack = parts[:9]

        features = builder.update(src, dst, length, ip_proto, fin, syn, rst, psh, ack)

        try:
            response = requests.post(
                "http://127.0.0.1:8000/predict",
                json=features
            )
            print(response.json())

        except Exception as e:
            print("FastAPI Bağlantı Hatası:", e)

    except Exception as e:
        pass
    


    