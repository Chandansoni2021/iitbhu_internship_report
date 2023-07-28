# iitbhu_internship_report

project-tittle - "Classification of IoT Attacks using Quantum Machine Learning" 

This repository contains the code and resources for a project focused on classifying IoT (Internet of Things) attacks using a QSVC (Quantum Support Vector Classifier) model. 
The primary aim of this project is to enhance the accuracy of attack classification  by incorporating bi-directional flow features, which provide valuable insights into the attack activity patterns.

## qiskit :-
This project focuses on leveraging the power of quantum computing for IoT attack classification. By combining the Qiskit library with QSVC (Quantum Support Vector Classifier), we aim to achieve more robust and efficient attack detection in IoT networks.

### new_flow_feature.py file description :-

in this code we extract the features of tcp/udp bi-directional flow . for extracting these features we use Scapy library for read the captured packet 

where total features are :- 

Feature Name	                     Description
stream           	      An identifier for each flow processed from the pcap file
packet_count	          Total number of packets in the flow
src_dst_len      	      Length of packets from source to destination in the flow
dst_src_len	            Length of packets from destination to source in the flow
freq_src_dst	          Frequency of packet lengths from source to destination in the flow
freq_dst_src	          Frequency of packet lengths from destination to source in the flow
prob_src_dst	          Probability of packets of the same length from source to destination in the flow
prob_dst_src	          Probability of packets of the same length from destination to source in the flow
total_prob_src_dst	    Total probability of packets of the same length from source to destination in the flow
total_prob_dst_src	    Total probability of packets of the same length from destination to source in the flow
total_prob	            Total probability of the packets of the same length the flow
AttackType	            The type of attack present in the flow (e.g., DoS, Malware, etc.)

### copy_of_QSVCNEW.ipynb file description :-

in this file we construct a model(QSVC model)to classify the iot attack

to find the best result we choose three feature which is given below :-

src_dst_len:- This feature represents the length of packets transmitted from the source to the destination in a network flow. In network traffic analysis, a flow typically refers to a sequence of related packets between two endpoints (e.g., source and destination). The "src_dst_len" feature quantifies the total length of data sent from the source to the destination in that flow.

dst_src_len:- This feature represents the length of packets transmitted from the destination to the source in a network flow. It is similar to the "src_dst_len" feature, but it captures the total length of data sent from the destination back to the source in that flow.

The "total_prob" feature represents the combined probability of two events related to the packets in the flow:-
   The probability that multiple packets with the same length are transmitted from the source to the destination.
   The probability that multiple packets with the same length are transmitted from the destination back to the source.

The "total_prob" feature quantifies the overall likelihood of observing these two events in the network flow. It's obtained by summing the individual probabilities of the two events.


for qsvc algorithm , there are may dependencies or version of library with qiskit 
which are given below :-

Qiskit version: 0.25.0
pandas: 1.5.3
numpy: 1.22.4


## Architecture:-
---
algorithm_globals.random_seed = 12345

backend = Aer.get_backend('aer_simulator')

adhoc_dimension = 4
adhoc_feature_map = ZZFeatureMap(feature_dimension=adhoc_dimension,
reps=2, entanglement="linear")
adhoc_kernel = QuantumKernel(feature_map=adhoc_feature_map,
quantum_instance=QuantumInstance(backend))

## Result:-
  
Dataset	    Quantity of dataset	     Training Size	    Testing Size	     Accuracy
Dataset 1	          300	                 240	              60	             75 %
Dataset 2         	100	                 80	                20	             80 %
Dataset 3	          500	                 400	              100            	 78 %
Dataset 4	          150	                 90	                60	             78 %
Dataset 5	          1000	               700	              300	             71 %





