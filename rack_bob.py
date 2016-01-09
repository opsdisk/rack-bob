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
# Retrive the rack binary
wget https://ec4a542dbf90c03b9f75-b342aba65414ad802720b41e8159cf45.ssl.cf5.rackcdn.com/1.1.0-beta1/Linux/amd64/rack
chmod +x rack
'''

''' The order of servers in the customer['servers'] list determines the order of the internal IP addresses assigned to the servers.'''
customer = {
                'internalNetworkName': 'INTERNAL-NETWORK',
                'CIDR': '10.10.20.0/24',
                'networkAndMask': '10.10.20.0 255.255.255.0',
                'gateway': '10.10.20.1',
                'allocationPool': 'start=10.10.20.2,end=10.10.20.254',
                'domain': 'example.com',
                'servers': [
                    {
                        'region': 'DFW',
                        'srvName': 'DB',
                        'imageName': 'Ubuntu 14.04 LTS (Trusty Tahr) (PVHVM)',
                        'flavorName': '2 GB General Purpose v1',
                        'ansibleRoles': ['common', 'DB'],
                    },

                ]
           }


class RackBob:

    def __init__(self, ansible, ssl, individualSSHkeys, prefixID, configFile):
        self.ansible = ansible
        self.ssl = ssl
        self.individualSSHkeys = individualSSHkeys
        self.prefixID = prefixID  
        
        self.configFile = configFile
        if self.configFile is not None:
            print("[*] Loading .json server config file")
            if os.path.isfile(self.configFile):
                with open(self.configFile) as jsonFile:
                    self.customer = json.load(jsonFile)
        else:
            print("[*] Loading server config from customer global dictionary")
            self.customer = customer
        
        self.customer['internalNetworkName'] = self.prefixID + '-' + self.customer['internalNetworkName']
        
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
        command = "./rack networks network create --name " + self.customer['internalNetworkName'] + self.postcommand  #+ " --region " + REGION
        resultsDict = json.loads(self.process_command(command)[0])
        self.networkID = resultsDict['ID']
        print("[+] Network ID: " + self.networkID)

    def add_subnet(self):
        # Add subnet
        print("[+] Creating subnet for network: " + self.networkID)
        command = "./rack networks subnet create --network-id " + self.networkID + " --name " + self.prefixID + "-SUBNET" + " --cidr " + self.customer['CIDR'] + " --gateway-ip " + self.customer['gateway'] + " --ip-version 4 --allocation-pool " + self.customer['allocationPool'] + " --dns-nameservers 8.8.8.8" + self.postcommand
        resultsDict = json.loads(self.process_command(command)[0])
        self.subnetID = resultsDict['ID']
        print("[+] Subnet ID: " + self.subnetID) 
   
    def build_servers(self):
        serverNum = 1
        keyName = self.prefixID + "-SSHKEY"
        
        if not self.individualSSHkeys:
            self.generate_ssh_key(keyName)

        for srv in self.customer['servers']:
            srv['srvName'] = self.prefixID + '-' + srv['srvName']

            if self.ansible:
                fh = open('ANSIBLE-PLAYBOOKS/' + srv['srvName'] + '.json', 'w')
            else:
                fh = open(srv['srvName'] + '.json', 'w')
            
            print("[*] Building server " + str(serverNum) + " / " + str(len(self.customer['servers'])))
            if self.individualSSHkeys:
                self.generate_ssh_key(keyName)

            srv['keyName'] = keyName

            # Create server
            print("[*] Creating server: " + srv['srvName'])
            rootPass = self.generate_password(32)
            rootPassHash = sha512_crypt.encrypt(rootPass)
            srv['rootPass'] = rootPass
            command = "./rack servers instance create --name " + srv['srvName'] + " --image-name '" + srv['imageName'] + "' --flavor-name '" + srv['flavorName'] + "' --networks 00000000-0000-0000-0000-000000000000," + self.networkID + " --admin-pass " + rootPass + " --keypair " + keyName + " --wait-for-completion " + self.postcommand
            resultsDict = json.loads(self.process_command(command)[0])
            serverID = resultsDict['ID']
            print("[+] Server ID: " + resultsDict['ID'])

            # Retreive final server information
            command = "./rack servers instance get --id " + serverID + self.postcommand
            resultsDict = json.loads(self.process_command(command)[0])

            # Retrieve internal server IP address
            command = "./rack servers instance list-addresses --id " + serverID + self.postcommand
            resultsList = json.loads(self.process_command(command)[0])
            for network in resultsList:
                if self.customer['internalNetworkName'] == network['Type']:
                    resultsDict['PrivateIPv4'] = network['Address']

            # Add custom keys to dictionary
            resultsDict['rootPass'] = rootPass
            resultsDict['rootPassHash'] = rootPassHash
            resultsDict['region'] = srv['region']
            resultsDict['flavorName'] = srv['flavorName']
            resultsDict['imageName'] = srv['imageName']
            resultsDict['keyNamePub'] = keyName + '.pub'
            resultsDict['CIDR'] = self.customer['CIDR']
            resultsDict['internalNetworkName'] = self.customer['internalNetworkName']
            resultsDict['gateway'] = self.customer['gateway']
            resultsDict['allocationPool'] = self.customer['allocationPool']
            resultsDict['domain'] = self.customer['domain']
            resultsDict['ansibleRoles'] = srv['ansibleRoles']
            resultsDict['networkAndMask'] = self.customer['networkAndMask']  #self.expand_cidr(resultsDict['CIDR'])

            # Save dictionary to file for records and/or further processing
            fh.write(json.dumps(resultsDict, sort_keys=False, indent=4, separators=(',', ': ')) + '\n')

            serverNum += 1

            fh.close()
            #print(str(srv))

            if self.ansible:
                # Generate hosts file
                fh = open('ANSIBLE-PLAYBOOKS/hosts', 'a')
                fh.write('[' + srv['srvName'] + ']' + '\n')
                fh.write(resultsDict['PublicIPv4'] + ' ansible_ssh_private_key_file=' + resultsDict['KeyName'] + '\n' * 2)
                fh.close()
                os.system('chmod -x ANSIBLE-PLAYBOOKS/hosts')

                # Place SSH keys in the right place
                os.system('mv ' + keyName + ' ANSIBLE-PLAYBOOKS')
                os.system('mv ' + keyName + '.pub ' + ' ANSIBLE-PLAYBOOKS/ssh_keys/')

                # Generate SSL certs
                if self.ssl:
                    print("[*] Generating a SSL certificate and key")
                    os.system('openssl req -x509 -nodes -days 730 -sha256 -newkey rsa:2048 -keyout ANSIBLE-PLAYBOOKS/ssl/' + resultsDict['Name'] + '.key -out ANSIBLE-PLAYBOOKS/ssl/' + resultsDict['Name'] + '.crt -subj "/C=US/ST=Arizona/L=Phoenix/O=Derp Inc/OU=NA/CN=derp"')

                # Generate site.yml variables
                fh = open('ANSIBLE-PLAYBOOKS/site.yml', 'a')
                fh.write('- hosts: ' + srv['srvName'] + '\n')
                fh.write('  user: root' + '\n')
                fh.write('  vars_files:' + '\n')
                fh.write('    - ' + resultsDict['Name'] + '.json' + '\n')
                fh.write('  roles:' + '\n')
                for r in resultsDict['ansibleRoles']:
                    fh.write('    - ' + r + '\n')
                fh.write('\n')
                fh.close()

    def process_command(self, command):
        #print(command)
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        proc.wait()
        stdout = proc.communicate()
        return stdout

    def generate_ssh_key(self, keyName):
        #command = "./rack servers keypair get --name " + keyName + self.postcommand
        command = "./rack servers keypair list" + self.postcommand
        resultsDict = json.loads(self.process_command(command)[0])
        
        # Determine if keyName exists on Rackspace            
        keyNameRemoteExist = False
        for key in resultsDict:
            if key['Name'] == keyName:
                print("[+] Public SSH key found on Rackspace: " + keyName)
                keyNameRemoteExist = True

        # Determine if keyName exists locally   
        keyNameLocalExist = False
        if (os.path.isfile(keyName) == keyName):  
            print("[+] Private SSH key found locally: " + keyName)
            keyNameLocalExist = True

        # If the SSH key does not exist locally or on Rackspace, create it
        if (not keyNameLocalExist) and (not keyNameRemoteExist):  
            print("[*] Generating 1 SSH key for: " + self.prefixID)
            command = "ssh-keygen -t rsa -b 4096 -C " + keyName + " -N '' -f " + keyName
            self.process_command(command)

            # Upload SSH key
            print("[*] Uploading SSH key: " + keyName)
            command = "./rack servers keypair upload --file " + keyName + ".pub" + " --name " + keyName + self.postcommand
            resultsDict = json.loads(self.process_command(command)[0])
        
        # If the SSH key does not exist locally, but does on Rackspace, delete remotely and regenerate    
        elif not keyNameLocalExist and keyNameRemoteExist:  
            print("[!] SSH key does not exist locally, but does on Rackspace.  Deleting remote SSH key and regenerating SSH keys")
            command = "./rack servers keypair delete --name " + keyName + ".pub" + " --name " + keyName + self.postcommand
            self.process_command(command)

            print("[*] Generating 1 SSH key for: " + self.prefixID)
            command = "ssh-keygen -t rsa -b 4096 -C " + keyName + " -N '' -f " + keyName
            self.process_command(command)

            # Upload SSH key
            print("[*] Uploading SSH key: " + keyName)
            command = "./rack servers keypair upload --file " + keyName + ".pub" + " --name " + keyName + self.postcommand
            resultsDict = json.loads(self.process_command(command)[0])

        # If the SSH key exists locally, but not on Rackspace, upload it
        elif keyNameRemoteExist and not keyNameRemoteExist:  
            print("[!] Key already exists locally: " + keyName)
            command = "./rack servers keypair upload --file " + keyName + ".pub" + " --name " + keyName + self.postcommand
        
        # If the SSH key exists locally and on Rackspace, skip
        elif keyNameLocalExist and keyNameRemoteExist:  
            print("[*] SSH keys already exist locally and on Rackspace: " + keyName)

        return

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

    def expand_cidr(self, CIDR):
        (addrString, cidrString) = CIDR.split('/')

        # Split address into octets and turn CIDR into int
        addr = addrString.split('.')
        cidr = int(cidrString)

        # Initialize the netmask and calculate based on CIDR mask
        mask = [0, 0, 0, 0]
        for i in range(cidr):
            mask[i / 8] = mask[i / 8] + (1 << (7 - i % 8))

        netmask = ".".join(map(str, mask))

        # Initialize net and binary and netmask with addr to get network
        net = []
        for i in range(4):
            net.append(int(addr[i]) & mask[i])

        network = ".".join(map(str, net))

        return network + ' ' + netmask


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Rack Bob the Builder')
    parser.add_argument('-a', dest='ansible', action='store_true', default=False, help='Make preparations to pass variables to Ansible')
    parser.add_argument('-c', dest='configFile', action='store', help='.json configuration file to read in with server details')
    parser.add_argument('-l', dest='ssl', action='store_true', default=False, help='Create individual SSL certificates and keys for each box')
    parser.add_argument('-p', dest='prefixID', action='store', type=str, default="123456", help='Server prefix ID (e.g., customer ID, Account number), default is 123456')
    parser.add_argument('-s', dest='individualSSHkeys', action='store_true', default=False, help='Create individual SSH keys for each box (default is to create 1 for all boxes)')
    args = parser.parse_args()

    rb = RackBob(**vars(args))
    rb.build()
    print("[+] Done!")