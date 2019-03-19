import socket
import struct

def parsing_ethernet_header(data):
	ethernet_header = struct.unpack("!6c6c2s",data)
	ether_src = convert_ethernet_address(ethernet_header[0:6])
	ether_dest = convert_ethernet_address(ethernet_header[6:12])
	ip_header = "0x"+ethernet_header[12].hex()

	print("======ethernet header=======")
	print("src_mac_address:",ether_src)
	print("dest_mac_address:",ether_dest)
	print("ip_version",ip_header)

def convert_ethernet_address(data):
	ethernet_addr = list()
	for i in data:
		ethernet_addr.append(i.hex())
	ethernet_addr = ":".join(ethernet_addr)
	return ethernet_addr

def parsing_ip_header(data):
	ip_header = struct.unpack("!1b1b2c2c2c1s1s2c4c4c",data)

	version_length = ip_header[0]
	ip_version = version_length >> 4
	ip_Length = version_length & 15

	DSF = ip_header[1]
	differentiated_service_codepoint = DSF >> 2 & 0x3F
	explict_congestion_notification = DSF & 0x03

	total_length = int(list_to_hex(ip_header[2:4]),16)

	identification = list_to_hex(ip_header[4:6])
	
	flags = list_to_hex(ip_header[6:8])
	intflags = int(flags)
	reserved_bit = intflags >> 15 & 0x01
	not_fragments = intflags >> 14 & 0x01
	fragments = intflags >> 13 & 0x01
	fragments_offset = intflags  
	
	Time_to_live = int(ip_header[8].hex(),16)
	protocol = int(ip_header[9].hex(),16)
	header_checksum = list_to_hex(ip_header[10:12])
	sourceip = convert_ip_header(ip_header[12:16])
	destip = convert_ip_header(ip_header[16:])

	print("======ip_header======")
	print("ip_version :", ip_version)
	print("ip_Length :",ip_version)
	print("differentiated_service_codepoint :", differentiated_service_codepoint)
	print("explicit_congestion_notification :", explict_congestion_notification)
	print("total_length :", total_length)
	print("identification : 0x"+identification)
	print("flags : 0x"+flags)
	print(">>>reserved_bit :",reserved_bit)
	print(">>>not_fragments :",not_fragments)
	print(">>>fragments :", fragments)
	print(">>>fragments_offset :",fragments_offset)
	print("Time to live :", Time_to_live)
	print("protocol :", protocol)
	print("header_checksum : 0x"+header_checksum)
	print("source_ip_address :",sourceip)
	print("dest_ip_address :",destip)

	return protocol

def convert_ip_header(data):
	ip_header = list()
	for i in data:
		ip_header.append(str(int(i.hex(),16)))
	ip_header = ".".join(ip_header)
	return ip_header

def parsing_tcp_header(data):
	tcp_header = struct.unpack("!2c2c4c4c2c2c2c2c",data)
	src_port = int(list_to_hex(tcp_header[0:2]),16)
	dec_port = int(list_to_hex(tcp_header[2:4]),16)
	seq_num = int(list_to_hex(tcp_header[4:8]),16)
	ack_num = int(list_to_hex(tcp_header[8:12]),16)
	header_flags = int(list_to_hex(tcp_header[12:14]),16)
	header_len = header_flags >> 12 & 15
	flags = header_flags >> 9 & 0x07
	reserved = header_flags >> 8 & 0x01
	nonce = header_flags >> 7 & 0x01
	cwr = header_flags >> 6 & 0x01
	urgent = header_flags >> 5 & 0x01
	ack = header_flags >> 4 & 0x01
	push = header_flags >> 3 & 0x01
	reset = header_flags >> 2 & 0x01
	syn = header_flags >> 1 & 0x01
	fin = header_flags & 0x01
	window_size_value = int(list_to_hex(tcp_header[15:17]),16)
	checksum = list_to_hex(tcp_header[17:19])
	urgent_pointer = int(list_to_hex(tcp_header[19:]),16)

	print("======tcp_header=====")
	print("src_port :",src_port)
	print("dec_port :",dec_port)
	print("seq_num :",seq_num)
	print("ack_num :",ack_num)
	print("header_len :",header_len)
	print("flahs :",flags)
	print(">>>reserved :",reserved)
	print(">>>nonce :",nonce)
	print(">>>cwr :",cwr)
	print(">>>push :", push)
	print(">>>reset :",reset)
	print(">>>syn :",syn)
	print(">>>fin :",fin)
	print("window_size_value :",window_size_value)
	print("checksum : 0x"+checksum)
	print("urgent_porinter :",urgent_pointer)


def parsing_udp_header(data):
	udp_header = struct.unpack("!2c2c2c2c",data)
	src_port = int(list_to_hex(udp_header[0:2]),16)
	dst_port = int(list_to_hex(udp_header[2:4]),16)
	leng = int(list_to_hex(udp_header[4:6]),16)
	header_checksum = list_to_hex(udp_header[6:8])

	print("======udp_header======")
	print("src_port :",src_port)
	print("dst_port :",dst_port)
	print("leng :",leng)
	print("header checksum : 0x"+header_checksum)

def list_to_hex(data):
	hex1 = list()
	for i in data:
		hex1.append(i.hex())
	hex1 = "".join(hex1)
	return hex1



	


while True:

	recv_socket = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0800))
	data = recv_socket.recvfrom(65565)

	parsing_ethernet_header(data[0][0:14])

	ip = parsing_ip_header(data[0][14:34])

	if(ip==6):
		parsing_tcp_header(data[0][34:54])
	elif(ip==17):
		parsing_udp_header(data[0][34:42])

