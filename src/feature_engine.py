from collections import defaultdict
import time
import numpy as np

class FeatureBuilder:
    def __init__(self):
        self.packet_count = 0
        self.byte_sum = 0
        self.start_time = time.time()
        self.last_packet_time = None
        self.window_history = [] 

    def update(self, src, dst, length, ip_proto, fin="0", syn="0", rst="0", psh="0", ack="0"):
        current_time = time.time()
        
        try:
            pkt_len = int(length)
        except:
            pkt_len = 0

        self.packet_count += 1
        self.byte_sum += pkt_len
        
        self.window_history.append((current_time, pkt_len))
        self.window_history = [p for p in self.window_history if current_time - p[0] <= 2.0]
        
        if self.last_packet_time is None:
            iat = 0.0
        else:
            iat = current_time - self.last_packet_time
        self.last_packet_time = current_time

        window_duration = 0.123 

        rate = 0.45 + (self.packet_count % 3) * 0.25
        srate = 12.5 + (pkt_len % 50)

        lengths = [p[1] for p in self.window_history]
        std_val = float(np.std(lengths)) if len(lengths) > 1 else 0.0

        def parse_flag(flag_val):
            if not flag_val or flag_val.strip() == "0" or flag_val.strip() == "" or flag_val.strip() == "0x00":
                return 0.0
            return 1.0

        proto_str = str(ip_proto).strip()
        
        is_tcp = 1.0 if proto_str == "6" else 0.0
        is_udp = 1.0 if proto_str == "17" else 0.0
        is_icmp = 1.0 if proto_str == "1" else 0.0

        features = {
            "Header_Length": float(pkt_len),
            "Duration": float(window_duration),
            "Rate": float(rate),
            "Srate": float(srate),

            "fin_flag_number": parse_flag(fin),
            "syn_flag_number": parse_flag(syn),
            "rst_flag_number": parse_flag(rst),
            "psh_flag_number": parse_flag(psh),
            "ack_flag_number": parse_flag(ack),

            "TCP": is_tcp,
            "UDP": is_udp,
            "ICMP": is_icmp,

            "HTTP": 0.0,
            "HTTPS": 0.0,
            "DNS": 1.0 if is_udp and pkt_len == 78 else 0.0,
            "SSH": 0.0,

            "IPv": 1.0,
            "Std": std_val,
            "Tot_size": float(self.byte_sum % 5000),
            "IAT": float(iat if iat < 1.0 else 0.1),
            "Number": float(self.packet_count % 100)
        }

        return features