import pyshark

capture = pyshark.LiveCapture(
    tshark_path=r"C:\Program Files\Wireshark\tshark.exe"
)

print(capture.interfaces)

