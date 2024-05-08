# ============================================================
# File:         FanOutRateCalculator.py
# Author:       Drake Young
# Last Updated: 10/4/2019
# Description:
# 	File contains the class object FanOutRateCalculator, a
#	utility object used for calculating the fan-out-rate
#	of every recorded source IP for the past 1s, 1min, and 5mins.
#	Program also will print that a scanner is detected if the
#	rates surpass a certain threshold for the various rates,
#	and specify which rate threshold was broken
# ============================================================

# ============================================================
# Imports:
# ============================================================
# 	-	threading.Thread: DictCleaner inherits from Thread
#	-	time.time: used to determine how old a packet is
# ============================================================
from threading import Thread
from time      import time


# ============================================================
# Class: FanOutRateCalculator
# ============================================================
# Description:
# 	Utility class used for calculating fan-out-rates and
#	reporting whether a port scanner has been detected
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
# run:
#	Overrides the threading.Thread run function which is called
#	when the thread is started.
#	Input:
#		-	N/A
#	Output:
#		-	No values returned
#		-	Output will be printed to console
#	Task:
#		-	This thread will iterate over the shared dictionary,
#			counting the number of times each IP address is
#			found within each of the desired time intervals
#			(past 1s, past 1min, past 5mins)
#		-	Once iteration is done, the lock is released, and
#			the logged fan out rates are compared to their
#			respective thresholds
#		-	if a rate exceeds its threshold, it is reported as
#			a detected port scanner, and the IP is blacklisted.
#			Blacklist is structures so that the same IP may
#			be reported once for surpassing each time threshold
#				e.g.	192.168.10.1 may be reported once
#						for exceeding the 1s threshold, then
#						reported again later for exceeding the
#						1min threshold, then a third time later
#						for exceeding the 5min threshold
# ============================================================
class FanOutRateCalculator( Thread ):
    ### CONSTRUCTOR __init___ ###
    def __init__( self , first_contacts , lock ):
        super( ).__init__( )
        self.first_contacts   =  first_contacts
        self.lock             =  lock
        self.is_running       =  True


    ### OVERRIDDEN METHOD run ###
    def run( self ):
        # === LOCAL VARIABLES === #
        ages             =  [ 1 ,  60 , 300 ] # 1=1s, 60=1min, 300=5mins
        max_connections  =  [ 5 , 100 , 300 ] # threshold connections for fan-out-rate to be scanner
        blacklist        =  dict( )           # used to avoid printing the same IP for the same reason endlessly

        # === RUN UNTIL TOLD EXTERNALLY TO STOP === #
        while self.is_running:
            source_connections  =  dict( ) # key=source IP, value= [ connections in past 1s, past 1min, past 5mins]

            # === BLOCKING WAIT UNTIL LOCK IS ACQUIRED === #
            with self.lock:
                current_time  =  time( ) # timestamp at start of iteration, so all are considered from a static reference

                # === ITERATE OVER KEYS IN SHARED DICTIONARY === #
                for key in self.first_contacts.keys( ):
                    source  =  key[0] # key[0] is the source IP

                    # === CALCULATE RATES FOR ALL TIME INTERVALS AT ONCE === #
                    for i in range( len( ages ) ): # 3, but made dynamic to be scalable
                        if current_time - self.first_contacts[key] < ages[i]: # within the time-scope for calculation
                            fan_out_rates               =  source_connections.get(source, [0,0,0]) # get current rates or default of all 0
                            fan_out_rates[i]           +=  1 # increment rate for appropriate time scope
                            source_connections[source]  =  fan_out_rates # store the updated value within a non-shared dict to safely release lock

            # === ITERATE OVER THE IP ADDRESSES RECORDED ABOVE === #
            for key in source_connections.keys( ):
                detected  =  False # Flag set if scanner is detected
                reason    =  ''    # Dynamically produce "reason" text at runtime

                # === COMPARE TO ALL THRESHOLDS === #
                for i in range( len( max_connections ) ): # 3, but made dynamic for scalability

                    # === IF CONNECTED MORE THAN THAT TIME INTERVAL'S THRESHOLD === #
                    if source_connections[key][i] > max_connections[i]: # if it connected more than threshold

                        # === IGNORE BLACKLISTED IP ADDRESSES === #
                        if i in blacklist.get( key , list( ) ):
                            continue
                        # === NOT A BLACKLISTED IP ADDRESS === #
                        else:
                            detected        =  True # Flag Detection
                            reason          =  'Reason: Fan-Out-Rate in the past {} seconds was {}  > {}'.format( ages[i] , source_connections[key][i] , max_connections[i] )
                            blacklist[key]  =  blacklist.get( key ,list( ) ) + [i] # Blacklist source ip and reason in order to not print again
                            break

                # === IF ANY IP HAS SURPASSED ANY THRESHOLD === #
                if detected:
                    print( 'Port Scanner Detected from IP Address: {}'.format( key ) )
                    fanout_per_1s = source_connections[key][2] / 300 # total connections / 300s (5min window)
                    fanout_per_1m = source_connections[key][1] / 5   # total connections / 5m (5min window
                    fanout_per_5m = source_connections[key][0] # total connections in past 5mins

                    # === PRINT FAN OUT RATE FOR ALL INTERVALS === #
                    print( '   Average Fan-Out Rate Per-Second Over the Last 5mins: {}'.format( fanout_per_1s ) )
                    print( '   Average Fan-Out Rate Per-Minute Over the Last 5mins: {}'.format( fanout_per_1m ) )
                    print( '   Average Fan-Out Rate Per-5-Minutes Over the Last 5mins: {}'.format( fanout_per_5m ) )
#                    for i in range( len( max_connections ) ): # 3, but left dynamic for scalability
#                        print( '   Fan-Out-Rate Per {}s (over past 5mins): {}'.format( ages[i] , ages[i] , source_connections[key][i] ) )

                    print( reason )
                    print( '' )
