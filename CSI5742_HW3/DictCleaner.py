# ============================================================
# File:         DictCleaner.py
# Author:       Drake Young
# Last Updated: 10/4/2019
# Description:
# 	File contains the class object DictCleaner, a utility
#   object used for removing objects from a shared dictionary
#   in a thread-safe way once their timestamp becomes outdated
#	by a specified amount
# ============================================================

# ============================================================
# Imports:
# ============================================================
# 	-	threading.Thread: DictCleaner inherits from Thread
#	-	time.time: used to determine whether an item has expired
# ============================================================
from threading import Thread
from time      import time


# ============================================================
# Class: DictCleaner
# ============================================================
# Description:
# 	Utility class used for clearing out expired items from a given
# 	shared dictionary in a thread-safe way
# ============================================================
# Methods
# ============================================================
# ___init___:
# 	Overrides the threading.Thread constructor
#	Input:
#		-	first_contacts: shared dictionary object
#		-	lock: threading.Lock object
#		-	max_age: number of seconds maximum that a value is
#			allowed to be kept in the first_contacts dictionary
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
#		-	the shared dictionary resource will receive added
#			values during runtime if a first-time-contact is
#			found
#	Task:
#		-	When this thread receives access to the Lock,
#			iterate over the first_contacts dictionary
#		-	record the keys of the dictionary whose timestamp
#			(value) is older than the max allowed age
# ============================================================
class DictCleaner( Thread ):
    ### __init__ CONSTRUCTOR ###
    def __init__( self , first_contacts , lock , max_age_seconds=300 ):
        super( ).__init__( )
        self.first_contacts  =  first_contacts
        self.lock            =  lock
        self.max_age_seconds =  max_age_seconds
        self.is_running      =  True


    ### OVERRIDDEN METHOD run ###
    def run( self ):
        # === CONTINUE UNTIL FLAG CHANGES EXTERNALLY === #
        while self.is_running:
            current_time    = time( ) # Time of reference
            keys_to_remove  = []      # Record of expired keys

            # === BLOCKING WAIT UNTIL LOCK IS ACQUIRED === #
            with self.lock:

                # === ITERATE KEYS IN SHARED DICTIONARY === #
                for key in self.first_contacts.keys( ):

                    # === IF KEY IS EXPIRED === #
                    if current_time - self.first_contacts[key] > self.max_age_seconds:
                        keys_to_remove.append( key )

                # === REMOVE ALL EXPIRED KEYS === #
                for key in keys_to_remove:
                    del self.first_contacts[key]
