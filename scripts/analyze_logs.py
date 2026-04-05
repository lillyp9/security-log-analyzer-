import pandas as pd 
import re

#open the file (txt.file)
file_path = 'data/ssh_logs.txt'

try:
    with open( file_path, 'r') as file:
        logs = file.readlines()
        print(len(logs))
    #catch error:
except FileNotFoundError:
    print(f"Error: The file'{file_path}'was not found.")
except Exception as e:
    print(f"An error occured: {e}")

#Parse the log file 
#extract 1 IP 

def parse_log_line(line):
    #extra the ip address using regex
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    ip_match = re.search(ip_pattern, line) #use match to determine if the index and series matchs the expression
    
    #Extract timestamp 
    time_pattern = r'\w{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}'
    time_match = re.search(time_pattern, line)
    
    if ip_match and time_match:
        return ip_match.group(), time_match.group()
    else:
        return None, None 
 

    
#tesing if code was able to etxraxt the logs 
#test_line = logs[0]
#print(f"Test line: {test_line.strip()}")
#print(f"Extracted IP: {parse_log_line(test_line)}")

#Extract all 430 log lines 
def parse_all_logs(logs):
    records = [] #placeholder
    for line in logs: #loop in every line 
        ip, timestamp = parse_log_line(line) #call parse_log_line in each line 
        if ip: 
            records.append({ #add to records 
                "ip": ip, #list of dict 
                "raw_line": line , #list of dict 
                "timestamp": timestamp
            })
    return pd.DataFrame(records) # create a dataframe 
df = parse_all_logs(logs)


#Note : looking at the output , same ip adress shown 3 times through log 1 to 3 
#same ip adress log 0 and 4 shown twice. indicates brute force 
#Which IP addresses appear the most times ?
#create new function
def detect_suspicious_ips(df, threshold = 10): # common threshold for 10 failed attempts.
    ip_counts = df.groupby("ip")["raw_line"].count().reset_index() #group ip check line then count have it added to the new index
    ip_counts.columns = ["ip", "count"] #column names 
    ip_counts = ip_counts.sort_values("count", ascending=False) #sort ipcounts , sort counts from highest to lowest
    suspicious_ips = ip_counts.loc[ip_counts['count'] > threshold] 
    top_attacker = ip_counts.sort_values('count', ascending=False).iloc[0]['ip']
    return suspicious_ips, ip_counts , top_attacker
#Note: had to create it into a new function to import it to generate_report.py
#Note:  Output shows that ip 91.240.118.172 has 200 attempts , 185.220.101.45 shows 114 attempts , 203.45.167.23 shows 106 attempts
#indicating that a 3 were attempst of brute force by attacker 
#IP with the highest number of attempts :
    

if __name__ == "__main__":
#all test prints below 
#show dataframe entries 
    print(f"Parse {len(logs)} log entries")
    print(df.head())
    
    

