# ============================================================
# File:         PS-Detector.py
# Author:       Drake Young
# Last Updated: 10/4/2019
# Description:
# 	Main file for this project. When this script is run, it
#	will perform a multithreaded approach to detecting a port
#	scanner ustilizing Sniffer.py, DictCleaner.py, and
#	FanOutRateCalculator.py each as an independent thread
#	with shared resources.
# ============================================================

# ============================================================
# Imports:
# ============================================================
#	-	threading: used for initializing the threading objects
#		and operating upon them
#	-	Sniffer.Sniffer: Sniffer class defined in Sniffer.py
#	-	DictCleaner.DictCleaner: DictCleaner class defined in
#		DictCleaner.py
#	-	FanOutRateCalculator.FanOutRateCalculator:
#		FanOutRateCalculator class defined in FanOutRateCalculator.py
# ============================================================
import threading
from Sniffer              import Sniffer
from DictCleaner          import DictCleaner
from FanOutRateCalculator import FanOutRateCalculator


# ============================================================
# Function: detect_ps
# ============================================================
# Description:
#	Main driver function for this program, initializing the
#	threaded classes imported above, and running them in
#	in parallel until an 'x' or an 'X' is input, which terminates
#	the program.
# Input:
#	-	N/A
# Output:
#	-	N/A
# Task:
#	-	Initialize Shared resource variables for the threads
#	-	Initialize and start each of the thread objects impored
#	-	Keep the function running in a while loop until 'x' or
#		'X' is input into the console
#	-	Set each thread's keep_running attribute to False
#		so that they they can safely terminates
#	-	join each thread into main to preven hanging on program
#		termination
# ============================================================
def detect_ps( ):
    # === SHARED VARIABLES === #
    first_contacts  =  dict( )
    lock            =  threading.Lock( )

    # === INITIALIZE THREAD OBJECTS === #
    sniffer                  =  Sniffer( first_contacts , lock )
    cleanup                  =  DictCleaner( first_contacts , lock )
    fan_out_rate_calculator  =  FanOutRateCalculator( first_contacts , lock )

    # === START THE TREADS === #
    sniffer.start( )
    cleanup.start( )
    fan_out_rate_calculator.start( )

    # === RUN UNTIL USER TELLS PROGRAM TO STOP === #
    print( '[+] Enter \'x\' to Stop Detecting' )
    while True:
        x  =  input( )
        if x in 'xX':
            print( '[*] Terminating Threads...' )
            break

    # === ALLOW THREADS TO ESCAPE THEIR INFINITE LOOPS === #
    sniffer.is_running                  =  False
    cleanup.is_running                  =  False
    fan_out_rate_calculator.is_running  =  False

    # === JOIN TO MAIN THREAD TO PREVENT HANGING
    sniffer.join( )
    cleanup.join( )
    fan_out_rate_calculator.join( )

    # === EXIT DRIVER FUNCTION === #
    return


# ============================================================
# Only call detector_ps during runtime when this function is the
# main script run, not when imported by another script (unless
# the importing script calls the function on its own)
# ============================================================
if __name__ == '__main__':
    detect_ps( )
