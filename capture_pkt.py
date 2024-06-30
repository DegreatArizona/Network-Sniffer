from scapy.all import sniff, UDP, IP

def packet_callback(packet):
    if UDP in packet:
        try:
            payload = packet[UDP].payload
            if payload:
                message = payload.load.decode('utf-8', errors='ignore')
                print(f"Packet captured from {packet[IP].src}:{packet[UDP].sport} to {packet[IP].dst}:{packet[UDP].dport}")
                print(f"Message: {message}")
            else:
                print(f"Packet captured from {packet[IP].src}:{packet[UDP].sport} to {packet[IP].dst}:{packet[UDP].dport} with no payload")
        except AttributeError:
            print(f"Packet captured from {packet[IP].src}:{packet[UDP].sport} to {packet[IP].dst}:{packet[UDP].dport} with no payload")
        except Exception as e:
            print(f"An error occurred while processing the packet: {e}")

def capture_packets(interface="eth0"):
    try:
        print(f"Starting packet capture on {interface}...")
        sniff(iface=interface, prn=packet_callback, filter="udp", store=0)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    capture_packets("eth0")  # Replace "eth0" with the correct interface name
