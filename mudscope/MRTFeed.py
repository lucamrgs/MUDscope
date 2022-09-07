
import pandas as pd
import json
import os
from pathlib import Path

class MRTFeed:
	"""
		Class that stores a MRT consisting of the MRT Evolution dataset, and metadata
	"""
	def __init__(self, metadata, csv_dataframe):
		if not (os.path.isfile(metadata) and os.path.isfile(csv_dataframe)):
			raise ValueError(f">>> ERROR: One or both files not found:\n>>> metadata file: {metadata}\n>>> csv dataframe: {csv_dataframe}")
		
		with open(metadata, 'r') as file:
			mtdt = json.load(file)
		self.id = Path(csv_dataframe).stem
		self.metadata = mtdt
		self.data = pd.read_csv(csv_dataframe)
		self.len = len(self.data.index)
		self.starts = self.data.iloc[0]['ch1_t_start']
		self.ends = self.data.iloc[-1]['ch2_t_end']
		self.duration = self.ends - self.starts
		#print(self.data)

	# TODO: metadata and feed validation

	def print_metadata(self):
		print(self.metadata)