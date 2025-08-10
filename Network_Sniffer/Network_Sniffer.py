from scapy.all import Ether, IP, TCP, UDP, ICMP, sniff
import datetime

seen_packets = set()  # Store seen packets to prevent duplicates

def packet_callback(packet):
    if IP in packet:  # Process only IP packets
        ip_layer = packet[IP]
        protocol = ip_layer.proto
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, "Unknown Protocol")
        src_port = "-"
        dst_port = "-"

        if protocol == 6 and TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif protocol == 17 and UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        packet_hash = f"{src_ip}:{src_port}->{dst_ip}:{dst_port} {protocol_name}"
        if packet_hash in seen_packets:
            return
        seen_packets.add(packet_hash)

        log_entry = f"""
        ------------------------------------------------------------------------------------------------
        Timestamp: {timestamp}                         Protocol: {protocol_name}
        Source IP: {src_ip}  Port: {src_port}          Destination IP: {dst_ip}  Port: {dst_port}
        ------------------------------------------------------------------------------------------------
        """
        print(log_entry)

        # Write to both log files
        for filename in ["sniffer_log.txt", "packet_log.txt"]:
            with open(filename, "a") as log_file:
                log_file.write(log_entry + "\n")

# Start sniffing with a limit of 25000 packets
print("Starting packet sniffing (max 25000 packets)...")
sniff(prn=packet_callback, store=False, count=25000)
print("Sniffer stopped.")