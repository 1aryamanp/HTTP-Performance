#!/usr/bin/python3
from scapy.all import *
import sys
import math
import numpy as np

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

    # read in the pcap file
    processed_file = rdpcap(pcap_filename)  

    for packet in processed_file:
        if packet.haslayer(TCP) and packet.haslayer(IP) and packet.haslayer(HTTP):
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            source_port = packet[TCP].sport
            dest_port = packet[TCP].dport

            if HTTPRequest in packet and dest_ip == server_ip and dest_port == server_port: #This was the issue, now its fixed
                # HTTP Request
                key = (source_ip, source_port)
                http_requests[key] = packet.time

            elif HTTPResponse in packet and source_ip == server_ip and source_port == server_port: 
                # HTTP Response
                key = (dest_ip, dest_port) #inverse as per the assignment
                if key in http_requests:
                    try:
                        # Calculate round-trip latency
                        latency = packet.time - http_requests[key]
                        latencies.append(latency)
                        del http_requests[key]  # Remove matched request
                    except KeyError:
                        pass  # Handle the case where request is not found

    return latencies

def exponential_cdf(x, lambda_param):
    x_float = float(x)  # Ensure x is a float
    lambda_float = float(lambda_param)  # Convert lambda_param to float
    return 1 - np.exp(-lambda_float * x_float)

def compute_prob_distribution(latencies, buckets):
    min_latency = float(min(latencies)) if latencies else 0.0
    max_latency = float(max(latencies))
    bucket_ranges = np.linspace(min_latency, max_latency, num=buckets + 1)
    counts, _ = np.histogram(latencies, bins=bucket_ranges)
    return counts / sum(counts) if counts.sum() > 0 else np.zeros(buckets)

def compute_kl_divergence(measured_dist, modeled_dist):
    kl_div = 0
    for p, q in zip(measured_dist, modeled_dist):
        if p > 0 and q > 0:
            kl_div += p * np.log(p / q)
        elif p > 0:
            return float('inf')  # Return infinity if p > 0 and q == 0
    return kl_div

    

# Main execution
if len(sys.argv) != 4:
    print("Usage: measure-webserver.py <input-file> <server-ip> <server-port>")
    sys.exit(1)

pcap_filename, server_ip, server_port = sys.argv[1:4]
latencies = process_packets(pcap_filename, server_ip, int(server_port))

if len(latencies) == 0:
    print("No HTTP request-response pairs found in the pcap file.")
    sys.exit(1)

average_latency = float(sum(latencies) / len(latencies))  # Ensure average_latency is a float
percentiles = calculate_percentiles(latencies)

# Compute the measured distribution
num_buckets = 10  # Define the number of buckets for the histogram
max_latency = float(max(latencies))  # Convert max_latency to float
bucket_ranges = np.linspace(0, max_latency, num_buckets + 1)  # Create bucket boundaries
measured_distribution = compute_prob_distribution(latencies, num_buckets)

# Compute the modeled distribution
lambda_param = 1 / average_latency
modeled_distribution = []
for i in range(num_buckets):
    lower_bound = bucket_ranges[i]
    upper_bound = bucket_ranges[i + 1]
    if i == num_buckets - 1:
        # Extend the upper bound for the last bucket to include all remaining latencies
        upper_bound = float('inf')
    prob_mass = exponential_cdf(upper_bound, lambda_param) - exponential_cdf(lower_bound, lambda_param)
    modeled_distribution.append(prob_mass)

kl_divergence = compute_kl_divergence(measured_distribution, modeled_distribution)

# Output
print("AVERAGE LATENCY: {:.5f}".format(average_latency))
print("PERCENTILES: {:.5f} {:.5f} {:.5f} {:.5f} {:.5f}".format(*percentiles))
print("KL DIVERGENCE: {:.5f}".format(kl_divergence))