from scapy.all import sniff, Ether

def packet_callback(packet):
    if Ether in packet:
        print(packet.summary())  # Print a summary of the packet

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
