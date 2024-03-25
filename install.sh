#!/bin/bash

# Update packages
sudo apt update 

# Install PostgreSQL
sudo apt-get install postgresql

# Create PostgreSQL user and database
sudo -u postgres psql -c "CREATE USER postgres;"
sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'test';"
sudo -u postgres psql -c "CREATE DATABASE test;"

# Install nmap
sudo apt-get install nmap

# Install Python3 and pip
sudo apt install python3 python3-dev
sudo apt install python3-pip

# Install Python requirements
pip3 install -r requirements.txt
pip3 install "censys==2.0.7; python_version > '3.8'" "censys==0.0.8; python_version <= '3.8'"

# Update packages again
sudo apt-get update

# Download and install Go
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -xvf go1.21.0.linux-amd64.tar.gz
sudo mv go /usr/local

# Set Go environment variables
echo 'export GOROOT=/usr/local/go' >> ~/.profile
echo 'export GOPATH=$HOME/go' >> ~/.profile
echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.profile
source ~/.profile

# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
