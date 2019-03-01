# Operation-Sledge

Sledge is a Python script designed to scan a CIDR-notated network for FTP servers and attempt to access them anonymously. Optionally, for any anonymous FTP servers found, it can be configured to download all files found in the FTP server's directory tree. For additional information on how to use this program or any others created, please visit https://madcityhacker.com.

# Setup
Sledge was written using Python 3.7. It has been tested on both Windows and Linux operating systems.

Installation
------------
Simply clone the repository and run `pip3 install -r requirements.txt`.

# Usage
This program can be run interactively or via command line arguments.

Interactive Mode
----------------
To run in interactive mode, simply run `python3 sledge.py`. You will be prompted for all required fields from there.

Automated Mode
--------------
There are a number of options that can be passed to the script.

 * -i or --ip <CIDR NETWORK> - This option specifies the CIDR-notated network to scan
 * -d or --download - This option downloads all files found in the anonymous FTP server's directory to the local system
 * -t or --threads <THREADS> - This option specifies how many threads to concurrently scan with (default: 10)
 
If one or more of these options are missing, they will be prompted for as they would if you were running the script in interactive mode.

Examples
--------
**Scan Class C Network**

`python3 sledge.py -i 192.168.1.0/24 -t 5`
 
 * The above will scan the IP addresses 192.168.1.0-192.168.1.255, utilizing 5 concurrent threads
  
**Scan Single Host & Download Files**

`python3 sledge.py -i 192.168.1.123/32 -d`
 
 * The above will scan the host 192.168.1.123 and download all files found if anonymous FTP is enabled
 
Licensing
---------
This program is licensed under GNU GPL v3. For more information, please reference the LICENSE file that came with this program or visit https://www.gnu.org/licenses/. 
 
Contact Us
----------
Whether you want to report a bug, send a patch, or give some suggestions on this program, please open an issue on the GitHub page or send an email to madcityhacker@gmail.com.