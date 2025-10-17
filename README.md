# busybeaver
Repoistory for educational purposes // Simulating and Preventing a SYN Flood Attack in a Virtual Cybersecurity Lab

# Objective
 - Simulate a TCP SYN flood attack using Kali Linux and hping3.
 - Monitor attack traffic with Wireshark.
 - Use Snort to detect and block malicious traffic.
 - Strengthen the target system with firewall rules and SYN cookies.

# Set up Lab
    echo "10.0.0.10 busybeaver.com" >> /etc/hosts

# Victim machine
## Set up Webserver (on victim machine)
    git clone https://github.com/it-kombinat/busybeaver
    cd busybeaver/
    sudo python3 -m http.server 80 &

## Base setup diagnostic tools
    sudo apt install snort wireshark-gtk bmon

## Wireshark
    sudo -E wireshark
    # Filter tcp.flags.syn == 1 and tcp.flags.ack == 0
    
# Launching the SYN Flood Attack
This created a flood of half-open connections on the Ubuntu server — the classic symptom of a SYN flood.
    
    hping3 -S --flood -p 80 -d 200 -w 64 10.0.0.10

`Command Breakdown`
- -S: Send SYN flag (starts handshake)
- --flood: Send packets continuously
- -p 80: Target port
- -d 200: Packet payload size
- -w 64: TCP window size
- 10.0.0.10: Target IP

# Mitigation Strategies
## Enable SYN Cookies
This tells the kernel to handle SYN floods more efficiently using stateless SYN-ACK replies.

    sudo sysctl -w net.ipv4.tcp_syncookies=1

## Apply iptables Rate Limiting
This limits new SYN connections to 10 per second, preventing overload.

    sudo iptables -A INPUT -p tcp — dport 80 — syn -m limit — limit 10/s — limit-burst 20 -j ACCEPT

## Block Attack IP
    sudo iptables -A INPUT -s 10.0.0.66 -j DROP

## Snort rule - Detect SYN FLOOD
    alert tcp any any -> any any (msg:"SYN Flood - High SYN rate from single IP"; flow:to_server,established; flags:S; threshold:type limit,track by_src,count 100,seconds 1; sid:1000001; rev:1;)
 
## Snort rule - Block Traffic
    drop tcp any any -> any 80 (msg:”Blocked TCP traffic to port 80"; sid:100002; rev:1;)

## Run snort
    sudo snort -A console -q -c syn.rules -i ens5
