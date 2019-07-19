# XShark
## Python wrapper to handle multiple TShark processes in one program.
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