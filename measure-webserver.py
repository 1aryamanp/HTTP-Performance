#!/usr/bin/python3
from scapy.all import *
import sys
import math

# Make sure to load the HTTP layer
load_layer("http")

def calculate_percentiles(latencies):
    latencies.sort()
    count = len(latencies)
    percentiles = [
        latencies[int(count * 0.25)],
        latencies[int(count * 0.50)],
        latencies[int(count * 0.75)],
        latencies[int(count * 0.95)],
        latencies[int(count * 0.99)],
    ]
    return percentiles

def process_packets(pcap_filename, server_ip, server_port):
    http_requests = {}
    latencies = []

    processed_file = rdpcap(pcap_filename)  # read in the pcap file

    for packet in processed_file:
        if packet.haslayer(TCP) and packet.haslayer(IP) and packet.haslayer(HTTP):
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            source_port = packet[TCP].sport
            dest_port = packet[TCP].dport

            if HTTPRequest in packet and dest_ip == server_ip and dest_port == server_port:
                # HTTP Request
                key = (source_ip, source_port)
                http_requests[key] = packet.time

            elif HTTPResponse in packet and source_ip == server_ip and source_port == server_port:
                # HTTP Response
                key = (dest_ip, dest_port)
                if key in http_requests:
                    try:
                        # Calculate round-trip latency
                        latency = packet.time - http_requests[key]
                        latencies.append(latency)
                        del http_requests[key]  # Remove matched request
                    except KeyError:
                        pass  # Handle the case where request is not found

    return latencies

# Main execution
if len(sys.argv) != 4:
    print("Usage: measure-webserver.py <input-file> <server-ip> <server-port>")
    sys.exit(1)

pcap_filename, server_ip, server_port = sys.argv[1:4]
latencies = process_packets(pcap_filename, server_ip, int(server_port))

if len(latencies) == 0:
    print("No HTTP request-response pairs found in the pcap file.")
    sys.exit(1)

average_latency = sum(latencies) / len(latencies)
percentiles = calculate_percentiles(latencies)
print("AVERAGE LATENCY: {:.5f}".format(average_latency))
print("PERCENTILES: {:.5f} {:.5f} {:.5f} {:.5f} {:.5f}".format(*percentiles))
