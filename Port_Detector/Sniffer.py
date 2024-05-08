# ============================================================
# File:         Sniffer.py
# Author:       Drake Young
# Last Updated: 10/4/2019
# Description:
# 	Adopted from Lab4, this packet sniffer has been constructed
#   as a class which inherits from threading.Thread. This
#	sniffer will constantly monitor traffic for as long as
#	its own thread
# ============================================================

# ============================================================
# Imports:
# ============================================================
#	-	socket: used for network connections
#	-	struct: used for unworking network packets
#	-	time.time: used to determine how old a packet is
# 	-	threading.Thread: DictCleaner inherits from Thread
# ============================================================
import socket
import struct
import time
from threading import Thread


# ============================================================
# Class: Sniffer
# ============================================================
# Description:
# 	Utility class used for capturing communication package
#	information and logging it in a thread-safe way
# ============================================================
# Methods
# ============================================================
# ___init___:
# 	Overrides the threading.Thread constructor
#	Input:
#		-	first_contacts: shared dictionary object
#		-	lock: threading.Lock object
#	Output:
#		-	N/A
#	Task:
#		-	initialize according to the parent class Thread.__init__
#		-	assign the parameters to their respective attributes
#		-	set the attribute flag is_running to True
#
#
# mac_format
#	Convert a packet's MAC address from packet format into
#	a readable/interpretable string format
#	Input:
#		-	mac: packet-format MAC address to be converted
#	Output:
#		-	String representation in a more readable format
#			of 2 characters at a time, separated by colons,
#			all uppercase
#	Task:
#		-	map the input into a {:02x} using string.format
#		-	convert the map into a string of uppercase letters
#		-	return the resulting string
#
#
# ipv4_format:
#	Convert the packet IPv4 address into a formatted string
#	representing the IP address
#	Input:
#		-	address: packet format of the ip address
#	Output:
#		-	string format of the input address
#	Task:
#		-	map the input to strings
#		-	join the mappings together using a '.' characters
#		-	return the resulting string
#
#
# ethernet_dissect:
#	Dissect the ethernet layer of the communication packet
#	into source MAC address, destination MAC address,
#	protocol id, and the remaining packet without the ethernet
#	headers.
#	Input:
#		-	ethernet_data: raw packet data at the ethernet level
#	Output:
#		1. String-Formatted destination MAC address
#		2. String-Formatted source MAC address
#		3. Protocol ID
#		4. Remaining packet (IP data)
#	Task:
#		-	unpack the appropriate amount of bytes from the
#			packet header (6 for destination MAC, 6 for
#			source MAC, 2 for Protocol)
#		-	format the source and destination MAC addresses
#			using mac_format
#		-	convert to appropriate bit order for protocol
#		-	return the values listed in "Output"
#
#
# ipv4_dissect:
#	Dissect the raw IP packet data to extract the IP protocol,
#	source and destination IP addresses, and the rest of the
#	packet contents.
#	Input:
#		-	ip_data: raw IP packet to be dissected
#	Output:
#		1. IP Protocol Code
#		2. String-Formatted Source IP Address
#		3. String-Formatted Destination IP Address
#		4. Remaining Packet without the IP header
#	Task:
#		-	Exclude the first 9 bytes. Irrelevant Metadata
#		-	Extract next byte as the protocol code
#		-	Exclude another 2 bytes. More Irrelevant Metadata
#		-	Next 4 bytes is 32-bit source IP address
#		-	Next 4 bytes is the 32-bit destination IP address
#		-	convert the extracted data into appropriate formats
#			using ipv4_format and socket.htons for the addresses
#			and protocol respectively
#		-	Return the formatted data in the order specified by
#			"Output"
#
#
# tcp_dissect:
#	Dissect the TCP protocol packet to retrieve the source
#	and destination ports.
#	Input:
#		-	transport_data: raw transport layer of the packet
#			with TCP protocol format expected
#	Output:
#		1. Source Port Number
#		2. Destination Port Number
#	Task:
#		-	First 2 bytes extracted are the source port
#		-	Next 2 bytes extracted are the destination port
#		-	Return these extracted values
#
#
# udp_dissect:
#	Dissect the UDP protocol packet to retrieve the source
#	and destination ports.
#	Input:
#		-	transport_data: raw transport layer of the packet
#			with UDP protocol format expected
#	Output:
#		1. Source Port Number
#		2. Destination Port Number
#	Task:
#		-	First 2 bytes extracted are the source port
#		-	Next 2 bytes extracted are the destination port
#		-	Return these extracted values
#
#
# icmp_dissect:
#	Dissect the ICMP protocol packet to retrieve the source
#	and destination ports.
#	Input:
#		-	transport_data: raw transport layer of the packet
#			with ICMP protocol format expected
#	Output:
#		1. ICMP Type
#		2. ICMP Code
#	Task:
#		-	First byte extracted is the ICMP Type
#		-	Next byte extracted is the ICMP Code
#		-	Return these extracted values
#
#
# run:
#	Overrides the threading.Thread run function which is called
#	when the thread is started.
#	Input:
#		-	N/A
#	Output:
#		-	No values returned
#		-	Shared first_contacts dictionary will be given
#			new/updated timestamp values as the thread runs
#	Task:
#		-	Set up the thread to receive raw packet data, with
#			a fixed timeout
#		-	until the is_running flag is externally set to False,
#			the thread will continue to receive incoming packets
#		-	Attempt to receive packet data, or re-iterate
#			if there is a timeout
#		-	ethernet_dissect the raw packet data
#		-	if the packet code represents IPv4, ipv4_dissect
#			the packet
#		-	either tcp_dissect, udp_dissect, or icmp_dissect
#			based on the IP porotocol
#		-	if the tuple (Source IP, Destination IP, Destination
#			Port) is unique, add it to the shared first_contacts
#			shared dictionary, with the tuple as the key, and the
#			time.time() timestamp as the values
#		-	Otherwise, update the existing timestamp in the
#			shared dictionary
#
# ============================================================
class Sniffer( Thread ):
    ### ___init___ CONSTRUCTOR ###
    def __init__( self , first_contacts , lock ):
        super( ).__init__( )
        self.first_contacts  =  first_contacts
        self.lock            =  lock
        self.is_running      =  True


    ### METHOD mac_format ###
    def mac_format( mac ):
        mac = map( '{:02x}'.format , mac )
        return ''.join( mac ).upper( )


    ### METHOD ipv4_format ###
    def ipv4_format( address ):
        return '.'.join( map( str , address ) )


    ### METHOD ethernet_dissect ###
    def ethernet_dissect( ethernet_data ):
        dest_mac, src_mac, protocol  =  struct.unpack( '!6s6sH' , ethernet_data[:14] )
        return Sniffer.mac_format( dest_mac ), Sniffer.mac_format( src_mac ), socket.htons( protocol ), ethernet_data[14:]


    ### METHOD ipv4_dissect ###
    def ipv4_dissect( ip_data ):
        ip_protocol, source_ip, target_ip = struct.unpack( '!9x B 2x 4s 4s', ip_data[:20] )
        return ip_protocol, Sniffer.ipv4_format( source_ip ), Sniffer.ipv4_format( target_ip ), ip_data[20:]


    ### METHOD tcp_dissect ###
    def tcp_dissect( transport_data ):
        source_port, dest_port  =  struct.unpack( '!HH' , transport_data[:4] )
        return source_port, dest_port


    ### METHOD udp_dissect ###
    def udp_dissect( transport_data ):
        source_port, dest_port  =  struct.unpack( '!HH' , transport_data[:4] )
        return source_port, dest_port


    ### METHOD icmp_dissect ###
    def icmp_dissect( transport_data ):
        icmp_type, icmp_code  =  struct.unpack( '!BB' , transport_data[:2] )
        return icmp_type, icmp_code


    ### OVERRIDDEN METHOD run ###
    def run( self ):
        packets  =  socket.socket( socket.PF_PACKET , socket.SOCK_RAW , socket.htons( 0x0800 ) )
        packets.settimeout( 5 ) # 5 second timeout to prevent hanging on recvfrom

        # === ITERATE UNLESS STOPPED EXTERNALLY === #
        while self.is_running:

            # === TRY RECEIVING WITH TIMEIOUT === #
            try:
                ethernet_data, address  =  packets.recvfrom( 65536 )

            # === RE-ITERATE ON TIMEOUT === #
            except socket.timeout:
                continue

            # === ETHERNET DISSECT === #
            dest_mac, src_mac, protocol, ip_data  =  Sniffer.ethernet_dissect( ethernet_data )

            # === IF IPV4 === #
            if protocol == 8:

                # === IPV4 DISSECT === #
                ip_protocol, src_ip, dest_ip, transport_data = Sniffer.ipv4_dissect( ip_data )
                contact  =  False

                # === IF TCP === #
                if ip_protocol == 6: # TCP

                    # === TCP DISSECT === #
                    src_port, dest_port  =  Sniffer.tcp_dissect( transport_data )
                    contact = True

                # === OTHERWISE IF UDP === #
                elif ip_protocol == 17: # UDP

                    # === UDP DISSECT === #
                    src_port, dest_port  =  Sniffer.udp_dissect( transport_data )
                    contact  =  True

                # === TCP OR UDP ONLY === #
                if contact:
                    key  =  ( src_ip , dest_ip , dest_port )

                    # === ONLY MODIFY SHARED DICTIONARY WHEN LOCK IS ACQUIRED === #
                    with self.lock:
                        self.first_contacts[key]  =  time.time( ) # create entry OR update timestamp
