# _SCHNOZ_
Advanced packet sniffer/analyzer and IDS with several options to conduct network monitoring and threat analysis

![Header](https://github.com/abelreqma/schnoz/assets/146870782/e151b47f-13fa-4f81-83b9-b5467779d564)


### Description 
Schnoz is a tool that I wrote in Python to monitor network traffic and analyze potential threats. I compiled all of the small scripts regarding network analysis to create a multirange tool.

### Features
When running the code, there are four options that a user can choose from:

**Active Sniffing (1)**:  Sniffs local traffic on a specified interface. Users must specify their intended interface based on _ifconfig_ and _Get-NetAdapter_. Users can choose any argument(s)

**File Sniffing (2)**: Sniffs pcap files. Users can choose any argument(s)

**Alert Mode (3)**: Sniffs through a specified interface or file for suspicious activity, alerting on potential malicious traffic. After choosing an interface or pcap file, the script then accepts either a wordlist or the schnozlist to alert off of. An alert will be printed with the packet summary if a term in either list is present in network traffic. I based the schnozlist on keywords that I’ve seen in CTFs, but more terms can be added if needed. 

**HTTP Analysis (4)**:  Analyzes HTTP packets (requests and responses) through an interface or a file. If -k is not specified, the script will print out all HTTP events. Only the argument of -k will work for this option. 

**Except for the keyword argument (-k), the arguments are only intended to be used with options 1 and 2.
Only Windows and Linux are currently supported (Linux users must comment out line 6)**


### Arguments
| Argument | Description |
| --- | --- |
| `-P` | Filters for protocol. Can use with -s y |
| `-p` | Filters for port. Can use with -s y |
| `-k` | Filters for a keyword and prints events  |
| `-o` | Saves file. Specify file name |
| `-s y` | Prints summaries of all events |
| `-s t` | Prints summaries of TCP events |
| `-s u` | Prints summaries of UDP events |
| `-s h` | Prints summaries of HTTP events |


### Examples
**Active Scanning**:![as1w](https://github.com/abelreqma/schnoz/assets/146870782/aba61386-e11b-414c-9aaa-0f75b48efee3)![as2w](https://github.com/abelreqma/schnoz/assets/146870782/02c9427a-eb89-42a9-b0ee-54a349749581)



**File Sniffing**:![fs1w](https://github.com/abelreqma/schnoz/assets/146870782/cacf4436-6093-41f6-a705-7784b0b191e0)![fs2w](https://github.com/abelreqma/schnoz/assets/146870782/7435583b-ec6f-4416-9fe4-2ccd1c08364e)

**Alert Mode**:![am1kl](https://github.com/abelreqma/schnoz/assets/146870782/8ce282ac-64b1-4a83-ad73-e8077f91681e)![am2kl](https://github.com/abelreqma/schnoz/assets/146870782/41f3381b-8cfa-413b-9e1e-0ce115f90029)

**HTTP Analysis**:![ha1w](https://github.com/abelreqma/schnoz/assets/146870782/aa47428a-c04e-4c73-abb8-357459d4fb5c)![ha2w](https://github.com/abelreqma/schnoz/assets/146870782/7a02fd7f-e08b-49f9-8773-532f7890b094)
![ha3w](https://github.com/abelreqma/schnoz/assets/146870782/cb5df739-e857-4941-915d-170ef51fe497)


**I am planning on expanding this program**
