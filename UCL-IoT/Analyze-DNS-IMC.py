#!/usr/bin/env python
# coding: utf-8

# In[1]:


#get_ipython().run_cell_magic('javascript', '', '\nIPython.tab_as_tab_everywhere = function(use_tabs) {\n    if (use_tabs === undefined) {\n        use_tabs = true; \n    }\n\n    // apply setting to all current CodeMirror instances\n    IPython.notebook.get_cells().map(\n        function(c) {  return c.code_mirror.options.indentWithTabs=use_tabs;  }\n    );\n    // make sure new CodeMirror instances created in the future also use this setting\n    CodeMirror.defaults.indentWithTabs=use_tabs;\n\n    };\n\nIPython.tab_as_tab_everywhere()')


# In[2]:


import os
import pandas as pd
import pickle
import subprocess
import json
import concurrent.futures
from tqdm import tqdm

# --------- Move this OUTSIDE the class ---------
def process_file(args):
	file_path, device_name, experiment_name, dataset_folder = args
	reader = IoTPcapReader(dataset_folder)  # create lightweight reader in subprocess
	packets = reader._run_tshark(file_path)
	data = []
	for packet in packets:
		if "_source" in packet and "layers" in packet["_source"]:
			row = {
				'Experiment Name': experiment_name,
				'Device Name': device_name,
				'Packet JSON': json.dumps(packet)
			}
			data.append(row)
	return pd.DataFrame(data)
# -----------------------------------------------

class IoTPcapReader:
	def __init__(self, dataset_folder: str):
		self.dataset_folder = dataset_folder
		self.global_dataframe = pd.DataFrame()

	def _run_tshark(self, file_path: str) -> list:
		try:
			cmd = ["tshark", "-r", file_path, "-T", "json"]
			result = subprocess.run(cmd, capture_output=True, text=True, check=True)
			packets = json.loads(result.stdout)
			return packets
		except Exception as e:
			print(f"Error running tshark on {file_path}: {e}")
			return []

	def read_all_pcap_files(self, max_workers=32):
		tasks = []
		for experiment_folder in os.listdir(self.dataset_folder):
			experiment_path = os.path.join(self.dataset_folder, experiment_folder)
			if os.path.isdir(experiment_path):
				for device_folder in os.listdir(experiment_path):
					device_path = os.path.join(experiment_path, device_folder)
					if os.path.isdir(device_path):
						for inner_folder in os.listdir(device_path):
							inner_path = os.path.join(device_path, inner_folder)
							if os.path.isdir(inner_path):
								for file_name in os.listdir(inner_path):
									if file_name.endswith('.pcap'):
										file_path = os.path.join(inner_path, file_name)
										tasks.append((file_path, device_folder, experiment_folder, self.dataset_folder))

		print(f"Total .pcap files found: {len(tasks)}")

		all_dfs = []
		with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
			futures = [executor.submit(process_file, task) for task in tasks]
			for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Processing PCAP files"):
				try:
					df_part = future.result()
					all_dfs.append(df_part)
				except Exception as e:
					print(f"⚠ Error processing file: {e}")

		if all_dfs:
			self.global_dataframe = pd.concat(all_dfs, ignore_index=True)
		else:
			print("⚠ No dataframes were generated — check your files.")

		print(f"✅ Completed reading. Total packets collected: {len(self.global_dataframe)}")

	def save_as_pickle(self, output_file: str):
		with open(output_file, 'wb') as f:
			pickle.dump(self.global_dataframe, f)
		print(f"✅ Dataset saved as pickle at {output_file}")

	def load_pickle(self, pickle_file: str):
		with open(pickle_file, 'rb') as f:
			self.global_dataframe = pickle.load(f)
		print(f"✅ Dataset loaded from pickle at {pickle_file}")

if __name__ == '__main__':
	dataset_folder_path = '../../Active-Experiments'
	output_pickle_path = 'output_dataset.pkl'

	iot_reader = IoTPcapReader(dataset_folder_path)
# 	iot_reader.read_all_pcap_files(max_workers=32)
# 	iot_reader.save_as_pickle(output_pickle_path)

	# Load and check the pickle file
	iot_reader.load_pickle(output_pickle_path)
	print(iot_reader.global_dataframe.head())


# In[3]:


iot_reader.global_dataframe["Packet JSON"][0]


# In[4]:


import os
import json
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
from datetime import datetime
from dateutil import parser
from collections import defaultdict

class DNSPacketAnalyzer:
	def __init__(self, global_dataframe: pd.DataFrame, output_folder: str = './dns_analysis_plots'):
		self.df = global_dataframe
		self.output_folder = output_folder
		os.makedirs(self.output_folder, exist_ok=True)
		self.preprocessed_df = None

	def preprocess_dns_packets(self):
		dns_records = []

		for _, row in self.df.iterrows():
			packet_json = json.loads(row.get('Packet JSON', '{}'))
			source = packet_json.get('_source', {})
			layers = source.get('layers', {})
			frame = layers.get('frame', {})
			dns = layers.get('dns', {})
			dns_flags = dns.get('dns.flags_tree', {})

			protocols = frame.get('frame.protocols', '')
			is_dns = 'dns' in protocols

			if is_dns:
				record = {
					'Device Name': row['Device Name'],
					'frame_time': frame.get('frame.time', ''),
					'frame_len': int(frame.get('frame.len', 0)) if frame.get('frame.len', '').isdigit() else 0,
					'protocols': protocols,
					'is_response': dns_flags.get('dns.flags.response', '') == '1',
					'queries': dns.get('Queries', {}),
					'answers': dns.get('Answers', {}),
					'edns': dns.get('dns.opt', ''),
				}

				record['ttl_list'] = [int(a.get('dns.resp.ttl', 0)) for a in record['answers'].values()] if record['answers'] else []
				record['query_types'] = [q.get('dns.qry.type', '') for q in record['queries'].values()] if record['queries'] else []
				record['query_names'] = [q.get('dns.qry.name', '') for q in record['queries'].values()] if record['queries'] else []

				dns_records.append(record)

		self.preprocessed_df = pd.DataFrame(dns_records)
		print(f"Preprocessed {len(self.preprocessed_df)} DNS packets.")

	def plot_bar(self, df, x, y, title, ylabel, filename, log_scale=False):
		plt.figure(figsize=(3.33, 2.2))
		plt.bar(df[x], df[y], width=0.6)
		if log_scale:
			plt.yscale('log')
		plt.xlabel(x, fontsize=7)
		plt.ylabel(ylabel, fontsize=7)
# 		plt.title(title, fontsize=7)
		plt.xticks(rotation=45, ha='right', fontsize=5.5)
		plt.yticks(fontsize=6)
		plt.tight_layout()
		plt.savefig(os.path.join(self.output_folder, filename), bbox_inches='tight', dpi=300)
		plt.close()

	def plot_dns_query_counts(self):
		summary = self.preprocessed_df.groupby('Device Name').size().reset_index(name='Number of Queries')
		self.plot_bar(summary, 'Device Name', 'Number of Queries', 'DNS Queries per Device', 'Queries', 'dns_query_counts.pdf')

	def plot_average_ttl(self):
		exploded = self.preprocessed_df.explode('ttl_list')
		exploded = exploded[exploded['ttl_list'] > 0]
		summary = exploded.groupby('Device Name')['ttl_list'].mean().reset_index()
		self.plot_bar(summary, 'Device Name', 'ttl_list', 'Average TTL per Device', 'Avg. TTL (log, s)', 'average_ttl_log.pdf', log_scale=True)

	def plot_dns_answer_counts(self):
		summary = self.preprocessed_df.explode('answers').groupby('Device Name').size().reset_index(name='Number of Answers')
		self.plot_bar(summary, 'Device Name', 'Number of Answers', 'DNS Answers per Device', 'DNS Answers', 'dns_answer_counts.pdf')

	def plot_dns_query_types(self):
		query_types = self.preprocessed_df.explode('query_names')
		counts = query_types.groupby(['Device Name', 'query_names']).size().reset_index(name='Count')
		pivot = counts.pivot(index='Device Name', columns='query_names', values='Count').fillna(0)
		ax = pivot.plot(kind='bar', stacked=True, figsize=(3.33, 2.5), width=0.6)
		plt.xlabel('Device Name', fontsize=7)
		plt.ylabel('Query Count', fontsize=7)
# 		plt.title('DNS Query Types per Device', fontsize=7)
		plt.xticks(rotation=45, ha='right', fontsize=6)
		plt.yticks(fontsize=6)
		plt.legend(fontsize=5, loc='upper right', frameon=False)
		plt.tight_layout()
		plt.savefig(os.path.join(self.output_folder, 'dns_query_types.pdf'), bbox_inches='tight', dpi=300)
		plt.close()

	def plot_avg_time_between_queries(self):
		times = self.preprocessed_df[~self.preprocessed_df['is_response']]
		times['parsed_time'] = pd.to_datetime(times['frame_time'], errors='coerce')
		times = times.dropna(subset=['parsed_time'])
		avg_times = times.sort_values('parsed_time').groupby('Device Name')['parsed_time'].apply(lambda x: x.diff().mean().total_seconds() if len(x) > 1 else 0).reset_index(name='Avg Time Between Queries')
		self.plot_bar(avg_times, 'Device Name', 'Avg Time Between Queries', 'Avg. Time Between DNS Queries', 'Avg. Time (log, s)', 'avg_time_between_queries_log.pdf', log_scale=True)

	def plot_distinct_addresses(self):
		addr_df = self.preprocessed_df.explode('answers')
		addr_df['dns_a'] = addr_df['answers'].apply(lambda a: a.get('dns.a') if isinstance(a, dict) else None)
		distinct_counts = addr_df.dropna(subset=['dns_a']).groupby('Device Name')['dns_a'].nunique().reset_index(name='Distinct Addresses')
		self.plot_bar(distinct_counts, 'Device Name', 'Distinct Addresses', 'Distinct DNS Addresses per Device', 'Distinct Addr.', 'distinct_addresses.pdf')

	def plot_avg_answers_per_frame(self):
		ans_df = self.preprocessed_df.copy()
		ans_df['answer_count'] = ans_df['answers'].apply(lambda a: len(a) if isinstance(a, dict) else 0)
		avg_ans = ans_df.groupby('Device Name')['answer_count'].mean().reset_index(name='Answers per Frame')
		self.plot_bar(avg_ans, 'Device Name', 'Answers per Frame', 'Avg. DNS Answers per Frame', 'Avg. Answers / Frame', 'average_answers_per_frame.pdf')

	def calculate_ipv6_query_percentage(self):
		ipv6_df = self.preprocessed_df.explode('query_types')
		total_counts = ipv6_df.groupby('Device Name').size()
		ipv6_counts = ipv6_df[ipv6_df['query_types'] == '28'].groupby('Device Name').size()
		percent_df = (ipv6_counts / total_counts * 100).fillna(0).reset_index(name='IPv6 Query Percentage')
		self.plot_bar(percent_df, 'Device Name', 'IPv6 Query Percentage', 'IPv6 Queries per Device', 'IPv6 Query %', 'ipv6_query_percentage.pdf')

	def calculate_average_retries(self):
		retries_df = self.preprocessed_df.explode('query_names')
		retries_count = retries_df.groupby(['Device Name', 'query_names']).size().reset_index(name='count')
		avg_retries = retries_count[retries_count['count'] > 1].groupby('Device Name')['count'].mean().reset_index(name='Average Retries')
		self.plot_bar(avg_retries, 'Device Name', 'Average Retries', 'Avg. DNS Query Retries per Device', 'Avg. Retries', 'average_dns_retries.pdf')

	def plot_query_rate(self):
		times = self.preprocessed_df[~self.preprocessed_df['is_response']]
		times['parsed_time'] = pd.to_datetime(times['frame_time'], errors='coerce')
		rate_df = times.dropna(subset=['parsed_time']).groupby('Device Name').apply(lambda x: len(x) / (x['parsed_time'].max() - x['parsed_time'].min()).total_seconds() if len(x) > 1 else 0).reset_index(name='Query Rate (queries/sec)')
		self.plot_bar(rate_df, 'Device Name', 'Query Rate (queries/sec)', 'DNS Query Rate per Device', 'Queries/sec', 'query_rate.pdf')

	def plot_protocol_distribution(self):
		proto_counts = defaultdict(lambda: defaultdict(int))
		for _, row in self.df.iterrows():
			device = row['Device Name']
			packet_json = json.loads(row.get('Packet JSON', '{}'))
			protocols = packet_json.get('_source', {}).get('layers', {}).get('frame', {}).get('frame.protocols', '')
			for proto in protocols.split(':'):
				proto_counts[device][proto] += 1
		proto_df = pd.DataFrame(proto_counts).fillna(0).T
		ax = proto_df.plot(kind='bar', stacked=True, figsize=(3.33, 2.5), width=0.6)
		plt.xlabel('Device Name', fontsize=7)
		plt.ylabel('Packet Count', fontsize=7)
		plt.yscale('log')
# 		plt.title('Protocol Distribution per Device', fontsize=7)
		plt.xticks(rotation=45, ha='right', fontsize=6)
		plt.yticks(fontsize=6)
		plt.legend(title='Protocols', fontsize=5, title_fontsize=6, bbox_to_anchor=(1.05, 1), ncols=4, frameon=False)
		plt.tight_layout()
		plt.savefig(os.path.join(self.output_folder, 'protocol_distribution.pdf'), bbox_inches='tight', dpi=300)
		plt.close()

	def plot_mdns_count(self):
		mdns_df = self.preprocessed_df[self.preprocessed_df['protocols'].str.lower().str.contains('mdns')]
		summary = mdns_df.groupby('Device Name').size().reset_index(name='MDNS Count')
		self.plot_bar(summary, 'Device Name', 'MDNS Count', 'MDNS Packet Count per Device', 'MDNS Packets', 'mdns_count.pdf')

	def analyze_dns_query_context(self, time_window=5):
		self.df['Timestamp'] = self.df['Packet JSON'].apply(
			lambda x: parser.parse(json.loads(x).get('_source', {}).get('layers', {}).get('frame', {}).get('frame.time', '')) if x else None)
		self.preprocessed_df['Timestamp'] = self.preprocessed_df['frame_time'].apply(
			lambda x: parser.parse(x) if x else None)

		query_contexts = []
		traffic_context_count = {}

		for _, dns_row in self.preprocessed_df.iterrows():
			dns_time = dns_row['Timestamp']
			device_name = dns_row['Device Name']
			dns_query = dns_row['queries']

			if dns_query:
				dns_query_name = list(dns_query.values())[0].get('dns.qry.name', '')

				related_packets = self.df[
					(self.df['Device Name'] == device_name) &
					(self.df['Timestamp'] >= dns_time - pd.Timedelta(seconds=time_window)) &
					(self.df['Timestamp'] <= dns_time + pd.Timedelta(seconds=time_window))
				]

				reasons = []

				for _, packet in related_packets.iterrows():
					packet_json = json.loads(packet['Packet JSON'])
					protocols = packet_json.get('_source', {}).get('layers', {}).get('frame', {}).get('frame.protocols', '')

					if 'tcp' in protocols and 'http' in protocols:
						reasons.append("HTTP Request after DNS")
					elif 'tcp' in protocols and 'tcp.analysis.retransmission' in packet_json.get('_source', {}).get('layers', {}).get('tcp', {}):
						reasons.append("TCP Retransmission before DNS")
					elif 'tcp' in protocols and 'tcp.flags.syn' in packet_json.get('_source', {}).get('layers', {}).get('tcp', {}):
						reasons.append("TCP SYN before DNS")
					elif 'dhcp' in protocols:
						reasons.append("DHCP before DNS")
					elif 'icmp' in protocols:
						reasons.append("ICMP before DNS")
					elif 'quic' in protocols:
						reasons.append("QUIC traffic near DNS")

				reasons = list(set(reasons))  # Remove duplicates

				query_contexts.append({
					'Device Name': device_name,
					'DNS Query': dns_query_name,
					'Query Time': dns_time,
					'Traffic Context': ', '.join(reasons) if reasons else "Unknown"
				})

				for reason in reasons:
					if device_name not in traffic_context_count:
						traffic_context_count[device_name] = {}
					if reason not in traffic_context_count[device_name]:
						traffic_context_count[device_name][reason] = 0
					traffic_context_count[device_name][reason] += 1

		query_context_df = pd.DataFrame(query_contexts)
		query_context_df.to_csv(os.path.join(self.output_folder, 'dns_query_context.csv'), index=False)
		print("DNS query context analysis completed. Results saved in 'dns_query_context.csv'.")

		self.plot_traffic_context_distribution(traffic_context_count)

		return query_context_df

	def plot_traffic_context_distribution(self, traffic_context_count):
		matplotlib.rcParams.update({'font.size': 7})  # ACM small font
		data = []
		for device, reasons in traffic_context_count.items():
			for reason, count in reasons.items():
				data.append({'Device Name': device, 'Traffic Context': reason, 'Count': count})

		df = pd.DataFrame(data)
		pivot_df = df.pivot(index='Device Name', columns='Traffic Context', values='Count').fillna(0)
		ax = pivot_df.plot(kind='bar', stacked=True, figsize=(3.33, 2.5), width=0.6)
		plt.xlabel('Device Name', fontsize=7)
		plt.ylabel('Context Count', fontsize=7)
# 		plt.title('Traffic Contexts Around DNS Queries', fontsize=7)
		plt.xticks(rotation=45, ha='right', fontsize=5.5)
		plt.yticks(fontsize=6)
		plt.legend(fontsize=5, bbox_to_anchor=(0.5, 1.30), ncols=2, frameon=False)
		plt.tight_layout()
		plt.savefig(os.path.join(self.output_folder, 'traffic_context_distribution.pdf'), bbox_inches='tight', dpi=300)
		plt.close()
		print("Traffic context distribution plot saved.")

	def plot_edns0_usage(self):
		edns_df = self.preprocessed_df[self.preprocessed_df['edns'] != '']
		summary = edns_df.groupby('Device Name').size().reset_index(name='EDNS(0) Count')
		self.plot_bar(summary, 'Device Name', 'EDNS(0) Count', 'EDNS(0) Usage per Device', 'EDNS(0) Count', 'edns0_usage.pdf')

	def analyze(self):
		self.preprocess_dns_packets()
		if not self.preprocessed_df.empty:
			self.plot_dns_query_counts()
			self.plot_average_ttl()
			self.plot_dns_answer_counts()
			self.plot_dns_query_types()
# 			self.plot_avg_time_between_queries()
			self.plot_distinct_addresses()
			self.plot_avg_answers_per_frame()
			self.calculate_ipv6_query_percentage()
			self.calculate_average_retries()
# 			self.plot_query_rate()
			self.analyze_dns_query_context()
			self.plot_protocol_distribution()
			self.plot_mdns_count()
			self.plot_edns0_usage()
			print(f"All plots saved to {self.output_folder}")
		else:
			print("No DNS packets found.")


# In[ ]:


import os
import pandas as pd
import pickle
import json
import concurrent.futures
from tqdm import tqdm

# Assuming DNSPacketAnalyzer is imported or defined here (as you provided)

def run_analyzer_for_experiment(experiment_name, experiment_df, base_output_folder):
	"""
	Run DNSPacketAnalyzer for a single experiment.
	"""
	output_folder = os.path.join(base_output_folder, experiment_name)
	analyzer = DNSPacketAnalyzer(experiment_df, output_folder=output_folder)
	analyzer.analyze()
	return f"✅ Completed analysis for {experiment_name}"

if __name__ == '__main__':
	# Paths
	input_pickle_path = 'output_dataset.pkl'
	base_output_folder = './dns_analysis_plots_active'

	# Group dataframe by experiment
	experiment_groups = {name: df for name, df in iot_reader.global_dataframe.groupby('Experiment Name')}
	print(f"Total experiments found: {len(experiment_groups)}")

	# Prepare tasks, skipping already completed ones
	tasks = []
	for experiment_name, experiment_df in experiment_groups.items():
		experiment_output_folder = os.path.join(base_output_folder, experiment_name)
		expected_result_file = os.path.join(experiment_output_folder, 'dns_query_counts.pdf')

		if os.path.exists(expected_result_file):
			print(f"⚠ Skipping {experiment_name} — results already exist.")
		else:
			tasks.append((experiment_name, experiment_df, base_output_folder))

	print(f"\nExperiments to analyze: {len(tasks)} (skipping {len(experiment_groups) - len(tasks)})")


	# Run analysis in parallel using 32 cores
	with concurrent.futures.ProcessPoolExecutor(max_workers=32) as executor:
		futures = [executor.submit(run_analyzer_for_experiment, exp_name, exp_df, base_output_folder) 
				   for exp_name, exp_df, base_output_folder in tasks]

		for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Analyzing Experiments"):
			try:
				result = future.result()
				print(result)
			except Exception as e:
				print(f"⚠ Error during analysis: {e}")

	print("✅ All experiment analyses completed.")

