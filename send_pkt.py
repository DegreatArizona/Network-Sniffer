import socket

def send_packets(target_ip, target_port, packet_count=10):
    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        char = int(input("Input amount of message: "))
        # Create a 100-byte message
        message = input("Input message: ") * char  # A message consisting of 100 'A' characters
        
        # Send packets
        for i in range(packet_count):
            sock.sendto(message.encode(), (target_ip, target_port))
            print(f"Packet {i+1} sent to {target_ip}:{target_port}")
        
        # Close the socket
        sock.close()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Configuration
    target_ip = input("Input target IP: ")  # Get target IP from user input
    target_port = int(input("Input target port: "))  # Get target port from user input and convert to integer
    packet_count = int(input("Input number of packets to send: "))  # Get number of packets to send and convert to integer

    send_packets(target_ip, target_port, packet_count)
