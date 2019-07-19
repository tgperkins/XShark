from multiprocessing import Process, Queue, Semaphore
import subprocess as sp
import os
from time import time
import sys
import getopt
from glob import glob

#help for options 
help = """
XShark
	example: python3 xshark.py -f "*.pcap" -c 6 -n -t "ip.dst ip.src" -s " "

	-d directory of pcaps to process
	-o output file
	-t tshark field options for example "ip.src ip.dst" no need for the -e for each
	-c concurrent subprocesses
	-n column names defaults to none
	-s separator use -s " " for space defaults to ","
	-V verbose
	-f files
"""

#TShark 
def tshark_process(pcap_name, fields, separator, lock, queue):
	lock.acquire()
	cmd = "tshark  -r " + pcap_name + " -T fields " + fields + " " + "-E separator=" + separator
	results = sp.run(cmd, shell=True, universal_newlines=True, stdout=sp.PIPE)
	queue.put(results.stdout)
	queue.close()
	lock.release()

if __name__ == "__main__":
	#Settings
	concurrent_processes = None
	directory = None
	packet_files = None
	fields = ""
	output = None
	verbose = False
	col_names = False
	col_name = False
	separator = ','

	try:
		opts, args = getopt.getopt(sys.argv[1:],"hd:o:Vt:c:ns:f:")
	except getopt.GetoptError:
		print ("Error in arguments")
		sys.exit()
	
	#Deal with the options
	for opt, arg in opts:
		if opt == "-h":
			print(help)
			sys.exit()

		if opt == "-d":
			directory = arg
			packet_files = os.listdir(arg)
			for i in range(len(packet_files)):
				packet_files[i] = directory + '/' + packet_files[i]

		if opt == "-c":
			cores = os.cpu_count()
			if int(arg) > cores:
				print("WARNING: More concurrent processes than cores continue?(y)")
				answer = input()
				if answer != "y":
					sys.exit()
			concurrent_processes = int(arg)

		if opt == "-o":
			output = arg

		if opt == "-n":
			col_name = True

		if opt == "-s":
			if arg == " ":
				#required by tshark 
				arg = "/s"
			separator = arg

		if opt == "-t":
			col_names = arg.split()
			for field in col_names:
				fields = fields + "-e {} ".format(field)
		
		if opt == "-V":
			verbose = True

		if opt == "-f":
			packet_files = glob(arg)

	#Clean up before starting
	if len(packet_files) < concurrent_processes:
		if verbose:
			print("WARNING: More concurrent processes than files decrementing number to be the same.")
		concurrent_processes = len(packet_files)

	if verbose:
		print("Files found: {}".format(len(packet_files)))
		print("Concurrent processes: {}".format(concurrent_processes))
		print("TShark fields: {}".format(fields))
		print("Starting subprocesses")

	#Workers
	count = Semaphore(concurrent_processes)
	processes = []
	results = Queue()

	for pcap in packet_files:
		p = Process(name="PCAP:" + pcap , target=tshark_process, args=(pcap, fields, separator, count, results))
		p.daemon = True
		processes.append(p)

	for process in processes:
		process.start()
	
	for process in processes:
		process.join()

	if separator == "/s":
			separator = " "

	#Print to terminal
	if output == None:
		if col_name == True:
			print(str.join(separator, col_names))
		while not results.empty():
			print(results.get())

	#Output to file
	else:
		try:
			open_file = open(output,'w')
			if col_name == True:
				open_file.write(str.join(separator, col_names) + '\n')
				while not results.empty():
					open_file.write(results.get())
		except Exception as e:
			print(e)
		open_file.close()
	results.close()
