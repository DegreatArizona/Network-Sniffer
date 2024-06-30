from scapy.all import sniff, IP

def packet_callback(packet):
    try:
        if IP in packet:
            timestamp = packet.time
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet.sprintf("%proto%")
            packet_info = f"{src_ip} → {dst_ip} {protocol}"

            if protocol == "TCP":
                info = packet[TCP].sprintf("%flags% Seq=%seq% Ack=%ack% Win=%window% Len=%len%")
                packet_info += f" {info}"
            elif protocol == "UDP":
                info = f"Len={len(packet[UDP])}"
                packet_info += f" {info}"

            print(f"{timestamp:.6f} {packet_info}")

    except Exception as e:
        print(f"An error occurred while processing the packet: {e}")

def capture_packets(interface="eth0", ip_address=None):
    try:
        print(f"Starting packet capture on {interface} for IP {ip_address}... (Press Ctrl+C to stop)")
        sniff(iface=interface, prn=packet_callback, filter=f"host {ip_address}")
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    target_ip = input("Enter the IP address to capture packets for: ")
    capture_packets("eth0", ip_address=target_ip)

