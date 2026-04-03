import sys
import pandas as pd
sys.path.append('.') #add current folder , to the search list
from scripts.generate_logs import attack_log
import time

#run loop with while True until something breaks it 
while True:
    attack_log() #call the attack log function to generate a new attack log line 
    time.sleep(5) #wait for 5 seconds before generating the next log line
    
