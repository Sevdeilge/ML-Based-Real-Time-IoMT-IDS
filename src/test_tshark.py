import subprocess

result = subprocess.run(
    [r"C:\Program Files\Wireshark\tshark.exe", "-D"],
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="ignore"
)

print(result.stdout)