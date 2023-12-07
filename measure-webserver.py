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
    number_of_packets_total = 0
    number_of_tcp_packets = 0
    http_requests = {}

    processed_file = rdpcap(pcap_filename)  # read in the pcap file
    latencies = []

    for packet in processed_file:
        number_of_packets_total += 1

        if packet.haslayer(TCP):  # check if the packet is a TCP packet
            number_of_tcp_packets += 1

            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            dest_port = packet[TCP].dport

            if packet.haslayer(HTTP):  # test for an HTTP packet
                if HTTPRequest in packet:
                    # HTTP Request
                    key = (source_ip, packet[TCP].sport)
                    http_requests[key] = packet.time
                elif HTTPResponse in packet:
                    # HTTP Response
                    key = (dest_ip, dest_port)
                    if key in http_requests:
                        # Calculate round-trip latency
                        latency = packet.time - http_requests[key]
                        latencies.append(latency)

                        # Remove matched request
                        del http_requests[key]

    return latencies

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