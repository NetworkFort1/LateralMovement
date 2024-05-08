# Homework 3: PortScanner Detector

"RBS detector measures the rate of connections to new destinations. It works based on the hypothesis that a scanning host contacts new destinations (IP+port) at a higher rate than a legitimate host does."

Jung, Jaeyeon, Rodolfo A. Milito, and Vern Paxson. "On the adaptive real-time detection of fast-propagating network worms." International Conference on Detection of Intrusions and Malware, and Vulnerability Assessment. Springer, Berlin, Heidelberg, 2007.

https://link.springer.com/content/pdf/10.1007%2Fs11416-007-0080-y.pdf

Inspired by the above methodology, in this homework you are using the expertise you learned in Lab 1 and 2 to build a tool that detects port scanners. This is a group project, but every student must submit individually. The project must be done through the full-fledged collaboration of all team members. You can make your own assumptions if you think any required information is missing from the description.

This tool will run on Kali VM and detect every host that is performing port scanning in the LAN where the Kali VM is located in. 

Note: You may not be able to see if your own machine is the port-scanner. Try to see if you can make this work. I will give additional points for it.

## Description

### Part 1 -- PortScanner Detector

Your program will be multi-threaded.

One thread of your program will sniff the traffic. For every connection from <srcIP, srcPort> to <dstIP, dstPort>, it records <(srcIP, dstIP, dstPort), timestamp> in a table. We refer to this as first-contact connection request. Every first-contact connection is stored for 5 minutes before being deleted. If (src, dstIP, dstPort) already exists, then you have already recorded the first-contact (do nothing). As a result of this step, you have a table (hashtable are a good option to implement this) of all first-contact connections per every source, along with their updated timestamp within the last 5 minutes. First-contacts that are older than 5 minutes must be constantly deleted (May need another thread). 

Another thread will calculate the fan-out rate of each source IP. Fan-out rate is the rate of establishing new connections per time interval. For example, the fan-out rate of 5/s means the source host has made 5 first-contact connections in the last second. 

You will calculate the fan-out rate for three different intervals: per second, per minute, per 5 minutes. 

If the fan-out rate per sec exceeds 5, or the fan-out rate per minute exceeds 100, or the fan-out rate per 5min exceeds 300 (any of these), the source IP is identified as a port-scanner.

Your program must output the source IP, the average fan-out rates per second in the last 5 minutes, the average fan-out rate per minute in the last 5 minutes, and the fan-out rate per 5 minutes for every detected port-scanner. Note that if a portscanner is detected in less than 5 minutes, some of these fan-out rates may not be applicable. I leave figuring out the details to you. Your program must also output the reason for detection (See example output below).

### Example Output
```
portscanner detected on source IP x
avg. fan-out per sec: y, avg fan-out per min: z, fan-out per 5min: d
reason: fan-out rate per sec = 6 (must be less than 5).
```

### Part 2 -- PortScanner

In lab 1, we developed a simple program that performs TCP port-scan. In this homework, you will update the portscanner. Your scanner will receive one more input: waiting time (milliseconds) between every two scans to different destinations (IP+port). Your port-scanner will respect this waiting time between every two consecutive scans. 

### Part 3 -- Test

You will set up your test environment. For this test, you need two Kali VMs. You can make a copy of the Kali VM that you already have to add another VM to your network. Let's call them Kali VM 1 (original) and Kali VM 2 (the copy you have added). Following guidelines in Lab 2, make sure Kali VM 2 belongs to the 192.168.10.*/24. In other words, Kali 1 and 2 both belong to the same LAN.

Run PS-Detector on Kali VM 1. 

On Kali VM 2, run your port-scanner. You will run it for 5 different scenarios with 5 different waiting times: 1 ms, 0.5s, 1s, 5s, 10s

You must submit the following in a zip folder:
1. PS-detector .py file.
2. Port scanner .py file.
3. A report that describes code, your LAN setup, and also screenshots of your results for each waiting time (5 total). Your report must include a discussion section, where you interpret your results. For example, why you did or did not detect the port-scanner. You must also describe your new assumptions that are not mentioned here.

There's no template for the report, but readability and appropriate formatting of the report will also affect your grade. 
