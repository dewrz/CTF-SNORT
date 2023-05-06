# CTF-SNORT Basics

Today I will be running through a blue team CTF focused on using the IDS/IPS Snort. Snort can be used both passively for packet analysis and in line with written rules to deny ports, IP ranges, etc. This is a CTF from TryHackMe and there are a number of questions that will need to be answered as we go along. 
<br>
<br>
<h4>Task 2 Writing IDS Rules (HTTP) Questions:</h4>
<br>
1. Write rules to detect "all TCP port 80 traffic" packets in the given pcap file. What is the number of detected packets? 
<br>
<br>
<b>Rules:</b>
alert tcp any any <> any 80 (msg:"TCP Port 80"; sid:1000001; rev:1;) 
alert tcp any 80 <> any any (msg:"TCP Port 80"; sid:1000002; rev:1;) 
<br>
<br>
<b>Command:</b>sudo snort -c local.rules -A full -l . -r mx-3.pca
<br>
<br>
<img src="https://i.imgur.com/Jh1YNII.jpg">
<br>
2. What is the destination address of packet 63?
<br>
<br>
<b>Command:</b> sudo snort –r snort.log.1683210946 -n 63
<br>
** By using the –n flag, we can limit the number of packets to quickly find the information needed. 
<br>
<br>
<img src="https://i.imgur.com/Jqoj4Iu.jpg">
<br>
The next 5 questions are about packets 62, 64 and 65. I’m going to run one command and take one screenshot to answer the following questions. 
<br>
<br>
3. What is the ACK number of packet 64? 

4. What is the SEQ number of packet 62? 

5. What is the TTL of packet number 65? 

6. What is the source IP of packet number 65? 

7. What is the source port of packet 65? 
<br>
<b>Command:</b> sudo snort -r snort.log.1683210946 -n 65
<br>
<br>
<img src="https://i.imgur.com/ZLh67fS.jpg">
<br>
<h4>Task 3 Writing IDS Rules (FTP) Questions:</h4>
<br>
1. Write rules to detect "all TCP port 21"  traffic in the given pcap.
What is the number of detected packets? 
<br>
<br>
<b>Rules:</b>
<br>
<br>
alert tcp any 21 <> any any (msg:"Who left FTP open?"; sid:1000001; rev:1;) 
alert tcp any any <> any 21 (msg:"Who left FTP open?"; sid:1000002; rev:1;) 
<br>
<br>
<b>Command:</b>sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap
<br>
<br>
<img src="https://i.imgur.com/Mo3dGeA.jpg">
<br>
2. What is the FTP service name?  
<br>
<br>
<img src="https://i.imgur.com/NKiADL5.jpg">
<br>
<br>











