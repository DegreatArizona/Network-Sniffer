from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    try:
        if IP in packet:
            timestamp = packet.time
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet.sprintf("%proto%")

            if protocol == "TCP" and packet[TCP].dport == target_port:
                info = packet[TCP].sprintf("%flags% Seq=%seq% Ack=%ack% Win=%window% Len=%len%")
                print(f"{timestamp:.6f} {src_ip} → {dst_ip} {protocol} {info}")
            elif protocol == "UDP" and packet[UDP].dport == target_port:
                info = f"Len={len(packet[UDP])}"
                print(f"{timestamp:.6f} {src_ip} → {dst_ip} {protocol} {info}")

    except Exception as e:
        print(f"An error occurred while processing the packet: {e}")

def capture_packets(interface="eth0", ip_address=None, port=None):
    global target_port
    target_port = port
    try:
        filter_str = f"host {ip_address} and port {port}"
        print(f"Starting packet capture on {interface} for IP {ip_address} and port {port}... (Press Ctrl+C to stop)")
        sniff(iface=interface, prn=packet_callback, filter=filter_str)
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    target_ip = input("Enter the IP address to capture packets for: ")
    target_port = int(input("Enter the port to capture packets for: "))
    capture_packets("eth0", ip_address=target_ip, port=target_port)
