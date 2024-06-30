from scapy.all import sniff, Ether, IP, TCP, UDP
import time

def format_packet(packet):
    timestamp = time.time()  # Current timestamp
    src_ip = packet[IP].src if IP in packet else ""
    dst_ip = packet[IP].dst if IP in packet else ""
    protocol = packet.summary().split()[2] if packet.haslayer(TCP) or packet.haslayer(UDP) else ""
    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        return f"{timestamp:.6f} {src_ip} → {dst_ip} TCP {sport} → {dport} [{flags}]"
    elif UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        return f"{timestamp:.6f} {src_ip} → {dst_ip} UDP {sport} → {dport}"
    elif IP in packet:
        return f"{timestamp:.6f} {src_ip} → {dst_ip} {protocol}"
    else:
        return f"{timestamp:.6f} Packet format not recognized"

def packet_callback(packet):
    print(format_packet(packet))

def capture_packets(interface="eth0", count=0):
    try:
        print(f"Starting packet capture on {interface}... (Press Ctrl+C to stop)")
        sniff(iface=interface, prn=packet_callback, count=count)
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    capture_packets("eth0", count=0)  # Replace "eth0" with your network interface
