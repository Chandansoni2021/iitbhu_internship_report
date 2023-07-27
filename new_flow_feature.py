import csv
from scapy.all import *
import os
from collections import Counter

c = 0
c = 0
MAX_FLOW_COUNT = 1000



def process_pcap(pcap_file, output_file, attack_type):
    global cimport numpy as np
import pandas as pd
df = pd.read_csv("/content/new3.csv")
    packets = rdpcap(pcap_file)
    flows = {}  # Dictionary to store flow information
    tcp_flow_count = 0
    udp_flow_count = 0
    

    for packet in packets:
        if IP in packet:
            if TCP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flow_key = (ip_src, ip_dst, sport, dport)
                rev_flow_key = (ip_dst, ip_src, dport, sport)

                if flow_key in flows:
                    flows[flow_key]['packet_count'] += 1
                    flows[flow_key]['total_length'] += len(packet)
                    flows[flow_key]['packet_lengths'].append(len(packet))
                    flows[flow_key]['src_to_dst_count'] += 1

                elif rev_flow_key in flows:
                    flows[rev_flow_key]['packet_count'] += 1
                    flows[rev_flow_key]['total_length'] += len(packet)
                    flows[rev_flow_key]['packet_lengths2'].append(len(packet))
                    flows[rev_flow_key]['dst_to_src_count'] += 1

                else:
                    flows[flow_key] = {
                        'packet_count': 1,
                        'total_length': len(packet),
                        'start_time': packet.time,
                        'packet_lengths': [len(packet)],
                        'packet_lengths2': [],

                        'src_to_dst_count': 1,
                        'dst_to_src_count': 0,
                    }
                    tcp_flow_count += 1

            elif UDP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                flow_key = (ip_src, ip_dst, sport, dport)
                rev_flow_key = (ip_dst, ip_src, dport, sport)

                if flow_key in flows:
                    flows[flow_key]['packet_count'] += 1
                    flows[flow_key]['total_length'] += len(packet)
                    flows[flow_key]['packet_lengths'].append(len(packet))
                    flows[flow_key]['src_to_dst_count'] += 1

                elif rev_flow_key in flows:
                    flows[rev_flow_key]['packet_count'] += 1
                    flows[rev_flow_key]['total_length'] += len(packet)
                    flows[rev_flow_key]['packet_lengths2'].append(len(packet))
                    flows[rev_flow_key]['dst_to_src_count'] += 1

                else:
                    flows[flow_key] = {
                        'packet_count': 1,
                        'total_length': len(packet),
                        'start_time': packet.time,
                        'packet_lengths': [len(packet)],
                        'packet_lengths2': [],
                        'src_to_dst_count': 1,
                        'dst_to_src_count': 0,
                    }
                    udp_flow_count += 1



    with open(output_file, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)

        for flow_key, flow_info in flows.items():
            packet_count = flow_info['packet_count']
            total_length = flow_info['total_length']
            flow_duration = packets[-1].time - flow_info['start_time']

            # Calculate flow rate
            flow_rate = total_length / flow_duration if flow_duration > 0 else 0

            # Calculate packet count ratio
            rev_flow_key = (flow_key[1], flow_key[0], flow_key[3], flow_key[2])
            rev_packet_count = flows.get(rev_flow_key, {'packet_count': 0})[
                'packet_count']

            src_ip = flow_key[0]
            dst_ip = flow_key[1]

            src_to_dst_count = flow_info['src_to_dst_count']
            dst_to_src_count = flow_info['dst_to_src_count']

            packet_lengths = flow_info['packet_lengths']  # for src to dst
            packet_lengths2 = flow_info['packet_lengths2']  # for dst to src
            total_freq = 0
            prob_total = total_freq/packet_count
            protocol = 'TCP' if TCP in packet else 'UDP'

            frequency = {}
            if (len(packet_lengths) > 0):

                for number in packet_lengths:
                    if number in frequency:
                        frequency[number] += 1
                    else:
                        frequency[number] = 1
            len1 = len(frequency)

            frequency2 = {}

            if (len(packet_lengths2) > 0):

                for number in packet_lengths2:
                    if number in frequency2:
                        frequency2[number] += 1
                    else:
                        frequency2[number] = 1
            len2 = len(frequency2)

            PROB = 0
            if (packet_count > 0):
                PROB = (len1+len2)/packet_count

# Printing the frequency of each number
            if (len(frequency) > 0):
                for number, count in frequency.items():
                    element2 = 0
                    # freq = count/src_to_dst_count
                    # freq2 = 0

                    prob_src_dst = 0
                    if (src_to_dst_count > 0):
                        prob_src_dst = count/src_to_dst_count
                        total_prob_dst_src = len1/src_to_dst_count

                        writer.writerow([

                            c, packet_count, number, element2, count, 0, prob_src_dst, 0, total_prob_dst_src, 0, PROB, attack_type
                        ])

                if (len(frequency2) > 0):

                    for number, count in frequency2.items():
                        element = 0
                        # freq2 = count/dst_to_src_count
                        # freq = 0
                        prob_dst_src = 0
                        if (dst_to_src_count > 0):
                            prob_src_dst = count/dst_to_src_count
                            prob_total_src_dst = len2/dst_to_src_count
                        writer.writerow([

                            c, packet_count, element, number, 0, count, 0, prob_src_dst, 0, total_prob_dst_src, PROB, attack_type
                        ])

            c = c+1
            
            if len(flows) >= MAX_FLOW_COUNT:
                break

        print(f"Flow features have been stored in {output_file}.")
        print(f"Total TCP flows: {tcp_flow_count}")
        print(f"Total UDP flows: {udp_flow_count}")
        print(f"Total flows: {tcp_flow_count + udp_flow_count}")


# Usage example
pcap_folder = r"C:\Users\Yash Kumar Soni\Desktop\pcap1"
output_file = r"C:\Users\Yash Kumar Soni\Desktop\new.csv"

with open(output_file, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow([
        'stream', 'packet_count',
        'src_dst_len', 'dst_src_len', 'freq_src_dst', 'frq_dst_src', 'prob_src_dst', 'prob_dst_src', 'total_prob_src_dst', 'total_prob_dst_src', 'total_prob', 'Attack Type'
    ])
total_flow_count = 0  # Initialize total_flow_count
for filename in os.listdir(pcap_folder):
    if total_flow_count >= MAX_FLOW_COUNT:
        break  # Stop processing pcap files if the flow count exceeds the limit

    file_path = os.path.join(pcap_folder, filename)
    attack_type = filename[:-5]
    process_pcap(file_path, output_file, attack_type)
    print("Finished processing one pcap")

print("Completed")
