import pandas as pd 
from datetime import datetime
import sys
sys.path.append('.') #add current folder , to the search list 
from scripts.analyze_logs import parse_all_logs, detect_suspicious_ips

#open text file , have the log entries print out 
with open('data/ssh_logs.txt', 'r') as file:
    logs = file.readlines()

df = parse_all_logs(logs)

suspicious_ips, ip_counts = detect_suspicious_ips(df)
#SSH SECURITY REPORT 
with open('reports/security_report.txt', 'w') as file: 
    today = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    file.write(f"Generated: {today}\n")
    file.write(f"Total log entries analyzed: {len(logs)}\n\n")
    file.write("SUSPICIOUS IPS DETECTED:\n")

# use zip to find the specific columns
    for ip, count in zip(suspicious_ips['ip'], suspicious_ips['count']):
        file.write(f"IP: {ip}, {count} attempts\n")