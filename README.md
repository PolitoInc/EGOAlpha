EGOVulnerabilityScanner
A vulnerability scanner created by chickenpwny @politoinc

Hello, I created ego to create an area for hackers to store many projects into a Rest API, I believed this to be a need so I developed ego. It utilizes many open-source security tools and libs to perform what I would call a comprehensive reconnoitering scan. For the time being, no documentation is provided I apologize but it was just been me developing the tool I do assume a fair amount of technical knowledge.

EGO provides a Rest API the recon agents can connect back to, this will allow pen testers to scan isolated networks and retrieve the nmap logs only needing to use HTTP protocol. pip3 install -r requirerments.txt install Postgres create a user postgres within recon a file settings.py change the DATABASES PASSWORD AND USER to the Postgres values.

sudo apt-get install nmap install https://github.com/projectdiscovery/nuclei

All the settings and switches for the agents are controlled by the rest API, the agents find the restapi by using /EGO_agent/EgoSettings.py

#EgoAgentUser = "EGO"
EgoAgentUser = "ego"
#EgoAgentPassWord = "password)"
EgoAgentPassWord = "password"
#HostAddress = "https://example.com"
HostAddress = "http://127.0.0.1"
Port = "5000"
api_accessKey = ""
To run EgoRecon.py

python3 EgoRecon.py
To run the nuclei python wrapper

python3 gnaw.py
to run ego custom web vuln scanner mantis.

python3 mantis.py
