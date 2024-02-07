# EGO Vulnerability Scanner

EGO is a vulnerability scanner developed by chickenpwny at PolitoInc. It was created to provide a platform for hackers to store multiple projects in a REST API. Recognizing a need for such a tool, EGO was developed to utilize various open-source security tools and libraries to perform comprehensive reconnaissance scans.

> **Note:** As this tool was developed by a single developer, it assumes a fair amount of technical knowledge and currently lacks documentation.

EGO provides a user-friendly GUI interface, eliminating the need for spreadsheets and files to record reconnaissance data. You can access the data using scripts or tools like Jupyter Notebook to interact with the database and identify vulnerabilities.

![demo](https://github.com/PolitoInc/EGOAlpha/assets/143764389/94619dd1-a8a3-420c-92b4-6c66f00ff0d7)

![improved](https://github.com/PolitoInc/EGOAlpha/assets/143764389/6e883648-d6f7-4c21-a4fb-94e05269ca80)

EGO also provides a REST API for reconnaissance agents to connect back to. This allows penetration testers to scan isolated networks and retrieve nmap logs using only the HTTP protocol.

## Installation

1. Install the required Python packages: 
2. Install Postgres and create a user named 'postgres'.
   ```
   sudo -i -u postgres psql
   CREATEUSER postgres;
   ALTER USER postgres WITH PASSWORD 'test';
   CREATE DATABASE test;
   \l -list
   \q
   ```
3. In the `settings.py` file, change the DATABASES PASSWORD AND USER to the Postgres values.
4. Install nmap:
   ```
   sudo apt-get install nmap
   ```
5. Install nuclei: First we need to install go1.21 [https://go.dev/doc/install](https://royzsec.medium.com/install-go-1-21-0-in-ubuntu-22-04-2-in-5-minutes-468a5330c64e)
```
sudo apt-get update
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -xvf go1.21.0.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
source ~/.profile

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

All settings and switches for the agents are controlled by the REST API. The agents find the REST API using `/EGO_agent/EgoSettings.py`.
## Configuration
```
EgoAgentUser = "ego" EgoAgentPassWord = "password" HostAddress = "http://127.0.0.1" Port = "5000" api_accessKey = ""
```
## Usage
To run EgoRecon.py: 
```
python3 EgoRecon.py
vim /etc/systemd/system/EGORecon.service

[Unit]
Description=Interactsh
After=network.target

[Service]
Type=simple
User=root
UMask=007
ExecStart= python3 manage runserver 0.0.0.0:5000
Restart=on-failure

# Configures the time to wait before service is stopped forcefully.
TimeoutStopSec=300

[Install]
WantedBy=multi-user.target
```
To run the nuclei python wrapper: 
```
python3 gnaw.py
```
To run the EGO custom web vulnerability scanner, mantis: 
```
python3 mantis.py
```
