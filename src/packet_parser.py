import subprocess

interface = r"\Device\NPF_{DC1DC608-7452-4AD2-B611-F3466ED1FCA3}"

cmd = [
    r"C:\Program Files\Wireshark\tshark.exe",
    "-i",
    interface,
    "-T",
    "fields",
    "-e",
    "ip.src",
    "-e",
    "ip.dst",
    "-e",
    "frame.len",
    "-e",
    "_ws.col.Protocol",
    "-c",
    "20"
]

result = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="ignore"
)

print(result.stdout)

