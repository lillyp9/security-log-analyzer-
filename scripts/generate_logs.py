import random
import pandas as pd
from datetime import datetime, timedelta

#setup 
suspicious_ips = [
    "203.45.167.23",
    "185.220.101.45",
    "91.240.118.172"
]

normal_ips = [
    "192.168.1.2",
    "192.168.1.5",
    "10.0.0.4",
    "172.16.0.8",
    "192.168.1.10"
]

usernames = ["root", "admin", "user", "lilly", "ubuntu", "user", "test", "pi"]
valid_users = ["lilly", "ubuntu"]
servers = ["server1", "webserver", "observer"]

#generate log line 
def generate_log (timestamp, ip , username, success=False):
    server = random.choice(servers)#calling random server 
    port = random.randint(1024, 65535) #calling random ports inbetween these 
    #condition 
    if success:
        event = f"Accepted Log In {username}"
    else: 
        event = f"Failed Log In {username}" 
    #Format
    line = f"{timestamp.strftime('%b %d %Y %H:%M:%S')} {server} sshd: {event} from {ip} port{port}"
    return line 

#gengerate new attack log line 

def attack_log():
    time_stamp = datetime.now()
    random_attack = random.choice(suspicious_ips)
    random_user = random.choice(usernames)

    new_line = generate_log(time_stamp, random_attack, random_user, False)
    with open('data/ssh_logs.txt', 'a') as file:
        file.write(new_line + '\n') #append to the log file    
    print(f"New attack log: {new_line}")


#generate timestamp
def generated_timestamp (start_time, timedelta):
    start_time = datetime(2024, 1, 1, 0, 0, 0)
    random_seconds = random.randint(0, 86400) # seconds in day
    return start_time + timedelta(seconds=random_seconds)


 
def log_file(output_file , days=30):
    logs = []
    start_date = datetime(2024, 1, 1)

    #condition
    for day in range(days):
        current_date = start_date + timedelta(days=day)

        #normal legit traffic
    for _ in range(random.randint(5, 15)):
        ip = random.choice(normal_ips)
        username = random.choice(valid_users)
        timestamp = current_date + timedelta(seconds=random.randint(0, 86400))
        success = random.random() > 0.2
        logs.append(generate_log(timestamp, ip, username, success))
        #brute force attacks 
    for attacker_ip in suspicious_ips:
        for _ in range(random.randint(50, 200)):
            username = random.choice(usernames)
            timestamp = current_date + timedelta(seconds=random.randint(0, 86400))
            logs.append(generate_log(timestamp, attacker_ip, username, False))

            #sort & save
        logs.sort()
        with open(output_file, 'w') as f:
            f.write('\n'.join(logs))
        print(f"Generate{len(logs)} of entries saved to {output_file}") 


    #Run the code 
if __name__ == "__main__":
   log_file("data/ssh_logs.txt")
