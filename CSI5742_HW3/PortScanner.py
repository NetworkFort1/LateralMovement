# Imports
import socket # Used for network connectivity
import time   # Used for timing



# Function: tcp_scan
# in: port -- integer representing port to test connection
# out: returns true if it could successfully connect, false otherwise
# task: attempt to connect to TCP port, if successful close connection and return True
#       otherwise return false
def tcp_scanner( target , port ):
    try:
        tcp_sock  =  socket.socket( socket.AF_INET , socket.SOCK_STREAM )
        tcp_sock.connect( ( target , port ) )
        return True
    except:
        return False
    finally:
        tcp_sock.close( )



# Function: main
# in: N/A, but input will be collected from console at runtime
# out: N/A, but a open ports will be printed to console as detected
# task: scan each port of target IP (1-1023) at the desired rate
# notes:
#    delay of d < 0.2 results in a fan out rate >5 per second
#    delay of 0.2 < d < 0.6 results in fan out rate >100 per minute
#    delay of 0.6 < d < 1 results in fan out rate >300 per 5mins
def port_scan( ):
    # Extract Target IP as string
    target = input('[+] Enter Target IP: ')
    delay_per_port = float(input('[+] Enter Delay Per-Port Scanned (Seconds): '))
    for portNumber in range( 1 , 2048 ):
        if tcp_scanner( target , portNumber ):
            print( '[*] Port {}/tcp is open'.format( portNumber ) )
        time.sleep( delay_per_port )



# Only run main if this file was called to run directly
if __name__ == '__main__':
    port_scan( )
