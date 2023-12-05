#!/usr/bin/python3

from scapy.all import *
import sys
import numpy as np

# Ensure the HTTP layer is loaded
load_layer("http")

# Function to calculate percentiles
def calculate_percentiles(latencies):
    return np.percentile(latencies, [25, 50, 75, 95, 99])

# Main function to process pcap file
def process_pcap(file_name, server_ip, server_port):
    latencies = []

    # Read pcap file
    packets = rdpcap(file_name)
    
    # Filter HTTP packets
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            if pkt[IP].dst == server_ip and pkt[TCP].dport == server_port:
                if pkt.haslayer(HTTPRequest):
                    # Record request time
                    req_time = pkt.time
                elif pkt.haslayer(HTTPResponse):
                    # Record response time and calculate latency
                    resp_time = pkt.time
                    latencies.append(resp_time - req_time)

    # Calculate average latency and percentiles
    avg_latency = np.mean(latencies)
    percentiles = calculate_percentiles(latencies)

    return avg_latency, percentiles

# Main execution
if __name__ == "_main_":
    if len(sys.argv) != 4:
        print("Usage: measure-webserver.py <input-file> <server-ip> <server-port>")
        sys.exit(1)

    input_file, server_ip, server_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    avg_latency, percentiles = process_pcap(input_file, server_ip, server_port)

    print(f"AVERAGE LATENCY: {avg_latency:.5f}")
    print(f"PERCENTILES: {percentiles[0]:.5f} {percentiles[1]:.5f} {percentiles[2]:.5f} {percentiles[3]:.5f} {percentiles[4]:.5f}")