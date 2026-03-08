from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        
        protocol = "Other"
        
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        
        print(f"Source: {src} --> Destination: {dst} | Protocol: {protocol}")

print("Sniffing network traffic... Press CTRL+C to stop")

sniff(prn=packet_callback)