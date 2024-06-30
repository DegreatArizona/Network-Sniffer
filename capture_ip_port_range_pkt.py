from scapy.all import sniff, IP, TCP, UDP

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

def capture_packets(interface="eth0", ip_address=None, port_range=None):
    try:
        filter_str = f"host {ip_address}"
        if port_range:
            filter_str += f" and portrange {port_range}"
        print(f"Starting packet capture on {interface} for IP {ip_address} and port range {port_range}... (Press Ctrl+C to stop)")
        sniff(iface=interface, prn=packet_callback, filter=filter_str)
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    target_ip = input("Enter the IP address to capture packets for: ")
    port_range = input("Enter the port range (e.g., 1000-2000): ")
    capture_packets("eth0", ip_address=target_ip, port_range=port_range)
