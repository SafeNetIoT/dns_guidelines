#!/usr/bin/env python
# coding: utf-8

# In[41]:


get_ipython().run_cell_magic('javascript', '', '\nIPython.tab_as_tab_everywhere = function(use_tabs) {\n    if (use_tabs === undefined) {\n        use_tabs = true; \n    }\n\n    // apply setting to all current CodeMirror instances\n    IPython.notebook.get_cells().map(\n        function(c) {  return c.code_mirror.options.indentWithTabs=use_tabs;  }\n    );\n    // make sure new CodeMirror instances created in the future also use this setting\n    CodeMirror.defaults.indentWithTabs=use_tabs;\n\n    };\n\nIPython.tab_as_tab_everywhere()')


# In[42]:


import os
import pandas as pd
import pickle
import subprocess
import json

class IoTPcapReader:
	def __init__(self, dataset_folder: str):
		"""
		Initialize the IoTPcapReader with the folder path.

		Args:
			dataset_folder (str): The path to the dataset folder containing device subfolders.
		"""
		self.dataset_folder = dataset_folder
		self.global_dataframe = pd.DataFrame()
		self.dns_dataframe = pd.DataFrame()

	def _run_tshark(self, file_path: str) -> list:
		"""
		Run tshark command to extract full packet details in JSON format.

		Args:
			file_path (str): Path to the pcap file.

		Returns:
			list: A list of complete packet details as dictionaries.
		"""
		try:
			cmd = ["tshark", "-r", file_path, "-T", "json"]
			result = subprocess.run(cmd, capture_output=True, text=True, check=True)
			packets = json.loads(result.stdout)
			return packets
		except Exception as e:
			print(f"Error running tshark on {file_path}: {e}")
			return []

	def _parse_packets(self, packets: list, device_name: str):
		"""
		Parse full packet JSON data and add it to the dataframe.

		Args:
			packets (list): List of packet details as dictionaries.
			device_name (str): Name of the IoT device.
		"""
		data = []

		for packet in packets:
			if "_source" in packet and "layers" in packet["_source"]:
				row = {
					'Device Name': device_name,
					'Packet JSON': json.dumps(packet)  # Store the full JSON as a string
				}
				data.append(row)

		temp_df = pd.DataFrame(data)
		self.global_dataframe = pd.concat([self.global_dataframe, temp_df], ignore_index=True)

	def _read_pcap_file(self, file_path: str, device_name: str):
		"""
		Read the contents of a pcap file and extract frame information using tshark.

		Args:
			file_path (str): Path to the pcap file.
			device_name (str): Name of the IoT device associated with the pcap file.
		"""
		packets = self._run_tshark(file_path)
		if packets:
			self._parse_packets(packets, device_name)

	def read_all_pcap_files(self):
		"""
		Read all pcap files from all device subfolders and store the data in a global dataframe.
		"""
		for device_folder in os.listdir(self.dataset_folder):
			device_path = os.path.join(self.dataset_folder, device_folder)
			if os.path.isdir(device_path):
				for file_name in os.listdir(device_path):
					if file_name.endswith('.pcap'):
						file_path = os.path.join(device_path, file_name)
						print(f"Reading file: {file_path}")
						self._read_pcap_file(file_path, device_folder)

	def save_as_pickle(self, output_file: str):
		"""
		Save the global dataframe as a pickle file.

		Args:
			output_file (str): The output pickle file path.
		"""
		with open(output_file, 'wb') as f:
			pickle.dump(self.global_dataframe, f)
		print(f"Dataset saved as pickle at {output_file}")

	def load_pickle(self, pickle_file: str):
		"""
		Load the dataset from a pickle file.

		Args:
			pickle_file (str): The path to the pickle file.
		"""
		with open(pickle_file, 'rb') as f:
			self.global_dataframe = pickle.load(f)
		print(f"Dataset loaded from pickle at {pickle_file}")

if __name__ == '__main__':
	# Example usage:
	dataset_folder_path = '../../baseline'
	output_pickle_path = '../../iot_data_baseline.pkl'
	dns_pickle_path = '../../dns_data_baseline.pkl' 

	# Create an object of IoTPcapReader
	iot_reader = IoTPcapReader(dataset_folder_path)

# 	# Read all pcap files and store data in the dataframe
# 	iot_reader.read_all_pcap_files()

# 	# Save the dataframe as a pickle file
# 	iot_reader.save_as_pickle(output_pickle_path)

	# Load and check the pickle file
	iot_reader.load_pickle(output_pickle_path)
	print(iot_reader.global_dataframe.head())


# In[43]:


print(iot_reader.global_dataframe["Packet JSON"][0])


# In[44]:


# import json
# import pandas as pd

# def expand_packet_json(global_dataframe: pd.DataFrame) -> pd.DataFrame:
# 	"""
# 	Expand the 'Packet JSON' column in the global dataframe into individual columns.

# 	Args:
# 		global_dataframe (pd.DataFrame): The dataframe containing the 'Packet JSON' column.

# 	Returns:
# 		pd.DataFrame: A new dataframe with individual fields from the JSON.
# 	"""
# 	expanded_data = []

# 	for _, row in global_dataframe.iterrows():
# 		packet_json = json.loads(row.get('Packet JSON', '{}'))
# 		layers = packet_json.get("_source", {}).get("layers", {})

# 		# Flattening the nested structure into individual columns
# 		expanded_row = {
# 			"Device Name": row.get("Device Name", ""),
# 			"Frame Time": layers.get("frame", {}).get("frame.time", ""),
# 			"Frame Number": layers.get("frame", {}).get("frame.number", ""),
# 			"Frame Length": layers.get("frame", {}).get("frame.len", ""),
# 			"Source MAC": layers.get("eth", {}).get("eth.src", ""),
# 			"Destination MAC": layers.get("eth", {}).get("eth.dst", ""),
# 			"Source IP": layers.get("ip", {}).get("ip.src", ""),
# 			"Destination IP": layers.get("ip", {}).get("ip.dst", ""),
# 			"Protocol": layers.get("frame", {}).get("frame.protocols", ""),
# 			"TCP Sequence Number": layers.get("tcp", {}).get("tcp.seq", ""),
# 			"UDP Length": layers.get("udp", {}).get("udp.length", ""),
# 			"DNS Transaction ID": layers.get("dns", {}).get("dns.id", ""),
# 			"DNS Flags": layers.get("dns", {}).get("dns.flags", ""),
# 			"DNS Query Name": layers.get("dns.qry", {}).get("dns.qry.name", ""),
# 			"DNS Answer Name": layers.get("dns.resp", {}).get("dns.resp.name", ""),
# 			"DNS Answer Address": layers.get("dns.resp", {}).get("dns.a", "")
# 		}

# 		expanded_data.append(expanded_row)

# 	expanded_df = pd.DataFrame(expanded_data)
# 	return expanded_df


# In[45]:


# # Assuming you have a global_dataframe with the "Packet JSON" column:
# expanded_df = expand_packet_json(iot_reader.global_dataframe)
# print(expanded_df.head())


# In[46]:


import os
import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from dateutil import parser

class DNSPacketAnalyzer:
	def __init__(self, global_dataframe: pd.DataFrame, output_folder: str = './dns_analysis_plots'):
		self.df = global_dataframe
		self.output_folder = output_folder
		os.makedirs(self.output_folder, exist_ok=True)

	def _filter_dns_packets(self):
		dns_rows = []
		for _, row in self.df.iterrows():
			packet_json = json.loads(row.get('Packet JSON', '{}'))
			protocols = packet_json.get('_source', {}).get('layers', {}).get('frame', {}).get('frame.protocols', '')
			if 'dns' in protocols:
				dns_rows.append(row)

		self.dns_df = pd.DataFrame(dns_rows)

	def plot_dns_query_counts(self):
		query_counts = self.dns_df.groupby('Device Name')['Packet JSON'].count().reset_index()
		query_counts.columns = ['Device Name', 'Number of Queries']

		plt.figure(figsize=(10, 6))
		plt.bar(query_counts['Device Name'], query_counts['Number of Queries'])
		plt.xlabel('Device Name')
		plt.ylabel('Number of Queries')
		plt.title('Number of DNS Queries per Device')
		plt.xticks(rotation=45, ha='right')
		plt.tight_layout()
		plt.savefig(os.path.join(self.output_folder, 'dns_query_counts.pdf'))
		plt.close()

	def plot_average_ttl(self):
		"""
		Plot the average TTL of replied RRs for each device, using a log scale on the y-axis.
		"""
		avg_ttl = []
		for _, row in self.dns_df.iterrows():
			packet_json = json.loads(row.get('Packet JSON', '{}'))
			answers = packet_json.get('_source', {}).get('layers', {}).get('dns', {}).get('Answers', {})
			ttls = [int(answer.get('dns.resp.ttl', 0)) for answer in answers.values() if 'dns.resp.ttl' in answer]
			avg_ttl_value = sum(ttls) / len(ttls) if ttls else 0
			avg_ttl.append({'Device Name': row['Device Name'], 'Average TTL': avg_ttl_value})

		avg_ttl_df = pd.DataFrame(avg_ttl).groupby('Device Name')['Average TTL'].mean().reset_index()

		plt.figure(figsize=(10, 6))
		plt.bar(avg_ttl_df['Device Name'], avg_ttl_df['Average TTL'])
		plt.yscale('log')  # Apply log scale (base 10)
		plt.xlabel('Device Name')
		plt.ylabel('Average TTL (log scale, seconds)')
		plt.title('Average TTL of DNS Replies per Device (Log Scale)')
		plt.xticks(rotation=45, ha='right')
		plt.tight_layout()
		plt.savefig(os.path.join(self.output_folder, 'average_ttl_log.pdf'))
		plt.close()

	def plot_dns_answer_counts(self):
		answer_counts = []
		for _, row in self.dns_df.iterrows():
			packet_json = json.loads(row.get('Packet JSON', '{}'))
			answers = packet_json.get('_source', {}).get('layers', {}).get('dns', {}).get('Answers', {})
			answer_count = len(answers)
			answer_counts.append({'Device Name': row['Device Name'], 'Number of Answers': answer_count})

		answer_counts_df = pd.DataFrame(answer_counts)
		answer_counts_summary = answer_counts_df.groupby('Device Name')['Number of Answers'].sum().reset_index()

		plt.figure(figsize=(10, 6))
		plt.bar(answer_counts_summary['Device Name'], answer_counts_summary['Number of Answers'])
		plt.xlabel('Device Name')
		plt.ylabel('Number of Answers')
		plt.title('Number of DNS Answers per Device')
		plt.xticks(rotation=45, ha='right')
		plt.tight_layout()
		plt.savefig(os.path.join(self.output_folder, 'dns_answer_counts.pdf'))
		plt.close()

	def plot_dns_query_types(self):
		query_types = []
		for _, row in self.dns_df.iterrows():
			packet_json = json.loads(row.get('Packet JSON', '{}'))
			queries = packet_json.get('_source', {}).get('layers', {}).get('dns', {}).get('Queries', {})
			for query in queries.values():
				query_name = query.get('dns.qry.name', '')
				query_types.append({'Device Name': row['Device Name'], 'Query Type': query_name})

		query_types_df = pd.DataFrame(query_types)
		query_counts = query_types_df.groupby(['Device Name', 'Query Type']).size().reset_index(name='Count')
		query_counts_pivot = query_counts.pivot(index='Device Name', columns='Query Type', values='Count').fillna(0)

		query_counts_pivot.plot(kind='bar', stacked=True, figsize=(12, 8))
		plt.xlabel('Device Name')
		plt.ylabel('Number of Queries')
		plt.title('DNS Query Types per Device')
		plt.xticks(rotation=45, ha='right')
		plt.tight_layout()
		plt.legend('',frameon=False)
		plt.savefig(os.path.join(self.output_folder, 'dns_query_types.pdf'))
		plt.close()

	def plot_avg_time_between_queries(self):
		"""
		Plot the average time between consecutive DNS queries per device in log scale.
		"""
		avg_times = []

		for device_name, device_df in self.dns_df.groupby('Device Name'):
			timestamps = []

			for _, row in device_df.iterrows():
				packet_json = json.loads(row.get('Packet JSON', '{}'))
				dns_layer = packet_json.get('_source', {}).get('layers', {}).get('dns', {})

				# Check if it's a DNS query (response flag == 0)
				is_query = dns_layer.get('dns.flags_tree', {}).get('dns.flags.response', '1') == '0'
				time_str = packet_json.get('_source', {}).get('layers', {}).get('frame', {}).get('frame.time', '')

				if is_query and time_str:
					try:
						# Use dateutil.parser to parse the timestamp automatically
						parsed_time = parser.parse(time_str)
						timestamps.append(parsed_time)
					except (ValueError, TypeError) as e:
						print(f"Invalid timestamp for {device_name}: {time_str} ({e})")
						continue

			if len(timestamps) > 1:
				timestamps = sorted(timestamps)
				time_differences = [(t2 - t1).total_seconds() for t1, t2 in zip(timestamps, timestamps[1:])]
				avg_time_between_queries = sum(time_differences) / len(time_differences)
			else:
				avg_time_between_queries = 0  # No valid consecutive queries to calculate

			avg_times.append({'Device Name': device_name, 'Avg Time Between Queries': avg_time_between_queries})

		avg_times_df = pd.DataFrame(avg_times)

		plt.figure(figsize=(10, 6))
		plt.bar(avg_times_df['Device Name'], avg_times_df['Avg Time Between Queries'])
		plt.yscale('log')
		plt.xlabel('Device Name')
		plt.ylabel('Average Time Between Queries (log scale, seconds)')
		plt.title('Average Time Between Consecutive DNS Queries per Device (Log Scale)')
		plt.xticks(rotation=45, ha='right')
		plt.tight_layout()
		plt.savefig(os.path.join(self.output_folder, 'avg_time_between_queries_log.pdf'))
		plt.close()

	def plot_distinct_addresses(self):
		"""
		Plot the number of distinct addresses returned by DNS responses for each device.
		"""
		distinct_addresses = []
		for _, row in self.dns_df.iterrows():
			packet_json = json.loads(row.get('Packet JSON', '{}'))
			answers = packet_json.get('_source', {}).get('layers', {}).get('dns', {}).get('Answers', {})
			addresses = {answer.get('dns.a', '') for answer in answers.values() if 'dns.a' in answer}
			distinct_addresses.append({'Device Name': row['Device Name'], 'Distinct Addresses': len(addresses)})

		distinct_addresses_df = pd.DataFrame(distinct_addresses).groupby('Device Name')['Distinct Addresses'].sum().reset_index()

		plt.figure(figsize=(10, 6))
		plt.bar(distinct_addresses_df['Device Name'], distinct_addresses_df['Distinct Addresses'])
		plt.xlabel('Device Name')
		plt.ylabel('Number of Distinct Addresses')
		plt.title('Number of Distinct DNS Addresses Returned per Device')
		plt.xticks(rotation=45, ha='right')
		plt.tight_layout()
		plt.savefig(os.path.join(self.output_folder, 'distinct_addresses.pdf'))
		plt.close()

	def plot_avg_answers_per_frame(self):
		"""
		Plot the average number of DNS answers per frame for each device.
		"""
		avg_answers = []
		for _, row in self.dns_df.iterrows():
			packet_json = json.loads(row.get('Packet JSON', '{}'))
			answers = packet_json.get('_source', {}).get('layers', {}).get('dns', {}).get('Answers', {})
			answer_count = len(answers)
			avg_answers.append({'Device Name': row['Device Name'], 'Answers per Frame': answer_count})

		avg_answers_df = pd.DataFrame(avg_answers).groupby('Device Name')['Answers per Frame'].mean().reset_index()

		plt.figure(figsize=(10, 6))
		plt.bar(avg_answers_df['Device Name'], avg_answers_df['Answers per Frame'])
		plt.xlabel('Device Name')
		plt.ylabel('Average Answers per Frame')
		plt.title('Average DNS Answers per Frame per Device')
		plt.xticks(rotation=45, ha='right')
		plt.tight_layout()
		plt.savefig(os.path.join(self.output_folder, 'average_answers_per_frame.pdf'))
		plt.close()

	def analyze(self):
		"""
		Perform DNS analysis and generate plots.
		"""
		self._filter_dns_packets()
		if not self.dns_df.empty:
			self.plot_dns_query_counts()
			self.plot_dns_answer_counts()
			self.plot_average_ttl()  # Log scale on Y-axis
			self.plot_avg_time_between_queries()  # New plot added
			self.plot_dns_query_types()
			self.plot_distinct_addresses()
			self.plot_avg_answers_per_frame()
			print(f"All plots have been saved in {self.output_folder}.")
		else:
			print("No DNS packets found.")


# In[47]:


# Assuming iot_reader.global_dataframe is already populated
dns_analyzer = DNSPacketAnalyzer(iot_reader.global_dataframe)

# Perform DNS analysis and generate/save plots
dns_analyzer.analyze()


# In[48]:


if __name__ == '__main__':
	# Example usage:
	dataset_folder_path = '../../DOH'
	output_pickle_path = '../../iot_data_doh.pkl'
	dns_pickle_path = '../../dns_data_doh.pkl' 

	# Create an object of IoTPcapReader
	iot_reader2 = IoTPcapReader(dataset_folder_path)

# 	# Read all pcap files and store data in the dataframe
# 	iot_reader.read_all_pcap_files()

# 	# Save the dataframe as a pickle file
# 	iot_reader.save_as_pickle(output_pickle_path)

	# Load and check the pickle file
	iot_reader2.load_pickle(output_pickle_path)
	print(iot_reader2.global_dataframe.head())


# In[49]:


# Assuming iot_reader.global_dataframe is already populated
dns_analyzer2 = DNSPacketAnalyzer(iot_reader2.global_dataframe, output_folder = './dns_analysis_plots_doh')

# Perform DNS analysis and generate/save plots
dns_analyzer2.analyze()

