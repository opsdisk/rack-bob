#!/usr/bin/env python
from __future__ import print_function

import argparse
import json
import os
import random
import string
import subprocess
import time

from passlib.hash import sha512_crypt
from ConfigParser import SafeConfigParser

'''
wget https://ec4a542dbf90c03b9f75-b342aba65414ad802720b41e8159cf45.ssl.cf5.rackcdn.com/1.1.0-beta1/Linux/amd64/rack
chmod +x rack
./rack configure
./rack servers instance list
'''

''' The order of servers in the customer['servers'] list determines the order of the internal IP addresses assigned to the servers.'''  
custID = "123456"
customer = {        
                'internalNetworkName': custID + '-INTERNAL-NETWORK',
                'CIDR': '10.10.20.0/24',
                'gateway': '10.10.20.1',
                'allocationPool': 'start=10.10.20.2,end=10.10.20.254',
                'servers': [
                    {
                        'region': 'DFW', 
                        'srvName': custID + '-DB',  # Database
                        'imageName': 'Ubuntu 14.04 LTS (Trusty Tahr) (PVHVM)',
                        'flavorName': '4 GB General Purpose v1',
                    },
                    {
                        'region': 'DFW',
                        'srvName': custID + '-WWW',  # Web front end
                        'imageName': 'Ubuntu 14.04 LTS (Trusty Tahr) (PVHVM)',
                        'flavorName': '4 GB General Purpose v1',
                    },                        
                ]
           }


class RackBob:

    def __init__(self, individualSSHkeys):
        self.individualSSHkeys = individualSSHkeys
        self.parse_creds()
        self.postcommand = " --output json --username " + self.username + " --api-key " + self.apiKey + " --region " + self.region

    def build(self):
        self.create_network()
        self.add_subnet()
        self.build_servers()
        print("[*] Sleeping for 10 seconds before querying instances")
        time.sleep(10)
        self.list_instances()

    def create_network(self):
        # Create network
        print("[*] Creating network")
        command = "./rack networks network create --name " + customer['internalNetworkName'] + self.postcommand  #+ " --region " + REGION
        resultsDict = json.loads(self.process_command(command)[0])
        self.networkID = resultsDict['ID']
        print("Network ID: " + self.networkID)

    def add_subnet(self):
        # Add subnet
        print("[+] Creating subnet for network: " + self.networkID)
        command = "./rack networks subnet create --network-id " + self.networkID + " --name " + custID + "-SUBNET" + " --cidr " + customer['CIDR'] + " --gateway-ip " + customer['gateway'] + " --ip-version 4 --allocation-pool " + customer['allocationPool'] + " --dns-nameservers 8.8.8.8" + self.postcommand
        resultsDict = json.loads(self.process_command(command)[0])
        self.subnetID = resultsDict['ID']
        print("Subnet ID: " + self.subnetID)

    def build_servers(self):
        serverNum = 1
        keyName = custID + "-SSHKEY"
        if not self.individualSSHkeys and not os.path.isfile(keyName):
            print("[*] Generating 1 SSH key for: " + custID)
            command = "ssh-keygen -t rsa -b 4096 -C " + keyName + " -N '' -f " + keyName
            self.process_command(command)
            # Upload SSH key
            print("[*] Uploading SSH key: " + keyName)
            command = "./rack servers keypair upload --file " + keyName + ".pub" + " --name " + keyName + self.postcommand
            resultsDict = json.loads(self.process_command(command)[0])
        else:
            print("[!] Key already exists locally: " + keyName)
            command = "./rack servers keypair upload --file " + keyName + ".pub" + " --name " + keyName + self.postcommand
            try:
                resultsDict = json.loads(self.process_command(command)[0])
            except:
                pass

        for srv in customer['servers']:
            fh = open(srv['srvName'] + '.json', 'w')
            print("[*] Building server " + str(serverNum) + " / " + str(len(customer['servers'])))
            if self.individualSSHkeys:
                print("[*] Generating SSH key for: " + srv['srvName'])
                # SSH_KEY, no passphrase
                keyName = custID + "-" + srv['srvName'] + "-SSHKEY"
                command = "ssh-keygen -t rsa -b 4096 -C " + keyName + " -N '' -f " + keyName
                self.process_command(command)
                
                # Upload SSH key
                print("[*] Uploading SSH key: " + keyName)
                command = "./rack servers keypair upload --file " + keyName + ".pub" + " --name " + keyName + self.postcommand
                resultsDict = json.loads(self.process_command(command)[0])
                       
            srv['keyName'] = keyName

            # Create server
            print("[*] Creating server: " + srv['srvName'])
            rootPass = self.generate_password(32)
            rootPassHash = sha512_crypt.encrypt(rootPass)
            srv['rootPass'] = rootPass
            command = "./rack servers instance create --name " + srv['srvName'] + " --image-name '" + srv['imageName'] + "' --flavor-name '" + srv['flavorName'] + "' --networks 00000000-0000-0000-0000-000000000000," + self.networkID + " --admin-pass " + rootPass + " --keypair " + keyName + " --wait-for-completion " + self.postcommand
            resultsDict = json.loads(self.process_command(command)[0])
            serverID = resultsDict['ID']
            print("Server ID: " + resultsDict['ID'])

            # Retreive final server information
            command = "./rack servers instance get --id " + serverID + self.postcommand
            resultsDict = json.loads(self.process_command(command)[0])
            
            # Retrieve internal server IP address    
            command = "./rack servers instance list-addresses --id " + serverID + self.postcommand
            resultsList = json.loads(self.process_command(command)[0])
            for network in resultsList:
                if customer['internalNetworkName'] == network['Type']:
                    resultsDict['PrivateIPv4'] = network['Address']

            # Add custom keys to dictionary
            resultsDict['rootPass'] = rootPass
            resultsDict['rootPassHash'] = rootPassHash
            resultsDict['region'] = srv['region']
            resultsDict['flavorName'] = srv['flavorName']
            resultsDict['imageName'] = srv['imageName']
            
            # Save dictionary to file for records and/or further processing
            fh.write(json.dumps(resultsDict, sort_keys=False, indent=4, separators=(',', ': ')) + '\n')
        
            serverNum += 1
    
            fh.close()
            #print(str(srv))

    def process_command(self, command):
        #print(command)
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        proc.wait()
        stdout = proc.communicate()
        return stdout

    def list_instances(self):
        for reg in ['DFW', 'IAD', 'ORD', 'LON', 'HKG', 'SYD']:
            print("Instances in region: " + reg)
            command = "./rack servers instance list --username " + self.username + " --api-key " + self.apiKey + " --region " + reg
            stdout = self.process_command(command)
            print(stdout[0])

    def generate_password(self, pwdSize):
        print("[*] Generating " + str(pwdSize) + "-character password")
        chars = string.letters + string.digits
        password = ''.join((random.choice(chars)) for x in range(pwdSize))
        return password

    def parse_creds(self):
        parser = SafeConfigParser()
        parser.read('rackspace_cloud_credentials.txt')
        self.username = parser.get('rackspace_cloud', 'username')
        self.apiKey = parser.get('rackspace_cloud', 'api_key')
        self.region = parser.get('rackspace_cloud', 'region')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Rack Bob the Builder')
    parser.add_argument('-s', dest='individualSSHkeys', action='store_true', default=False, help='Create individual SSH keys for each box (default is to create 1 for all boxes)')
    args = parser.parse_args()

    rb = RackBob(**vars(args))
    rb.build()
    print("[+] Done!")