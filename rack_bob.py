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
                'networkAndMask': '10.10.20.0 255.255.255.0',
                'gateway': '10.10.20.1',
                'allocationPool': 'start=10.10.20.2,end=10.10.20.254',
                'domain': 'example.com',
                'servers': [
                    {
                        'region': 'DFW', 
                        'srvName': custID + '-PB-VPN',  # Database
                        'imageName': 'Ubuntu 14.04 LTS (Trusty Tahr) (PVHVM)',
                        'flavorName': '2 GB General Purpose v1',
                        'ansibleRoles' : ['common', 'PB-VPN'], # 'phpmyadmin'],
                    },
                                         
                ]
           }
                    

'''
                    {
                        'region': 'DFW', 
                        'srvName': custID + '-PB-DB',  # Database
                        'imageName': 'Ubuntu 14.04 LTS (Trusty Tahr) (PVHVM)',
                        'flavorName': '2 GB General Purpose v1',
                        'ansibleRoles' : ['common', 'PB-WWW'],
                    },
                    {
                        'region': 'DFW', 
                        'srvName': custID + '-PB-WWW',  # Database
                        'imageName': 'Ubuntu 14.04 LTS (Trusty Tahr) (PVHVM)',
                        'flavorName': '2 GB General Purpose v1',
                        'ansibleRoles' : ['common', 'PB-WWW'],
                    },
                    {
                        'region': 'DFW',
                        'srvName': custID + '-PB-MAIN',  # PB email processor
                        'imageName': 'Ubuntu 14.04 LTS (Trusty Tahr) (PVHVM)',
                        'flavorName': '8 GB General Purpose v1',
                        'ansibleRoles' : ['common', 'PB-MAIN'],
                    },
                    {
                        'region': 'DFW',
                        'srvName': custID + '-PB-RESEARCH',  # Performs HTTP 301/302 lookups
                        'imageName': 'Ubuntu 14.04 LTS (Trusty Tahr) (PVHVM)',
                        'flavorName': '2 GB General Purpose v1',
                        'ansibleRoles' : ['common', 'PB-RESEARCH'],
                    },
                    {
                        'region': 'DFW',
                        'srvName': custID + '-PB-ENFORCER',  # Listens for user-released emails and sends them
                        'imageName': 'Ubuntu 14.04 LTS (Trusty Tahr) (PVHVM)',
                        'flavorName': '2 GB General Purpose v1',
                        'ansibleRoles' : ['common', 'PB-ENFORCER'],
                    },
                    {
                        'region': 'DFW',
                        'srvName': custID + '-PB-CUCKOO',  # Listens for user-released emails and sends them
                        'imageName': 'Ubuntu 14.04 LTS (Trusty Tahr) (PVHVM)',
                        'flavorName': '8 GB General Purpose v1',
                        'ansibleRoles' : ['common', 'PB-CUCKOO'],
                    },      
                    '''                


class RackBob:

    def __init__(self, ansible, ssl, individualSSHkeys):
        self.ansible = ansible
        self.ssl = ssl
        self.individualSSHkeys = individualSSHkeys
        self.parse_creds()
        self.postcommand = " --output json --username " + self.username + " --api-key " + self.apiKey + " --region " + self.region

    def build(self):
        self.create_network()
        self.add_subnet()
        self.build_servers()
        #if self.ansible:
        #    self.append_ansible_roles()
        print("[*] Sleeping for 10 seconds before querying instances")
        time.sleep(10)
        self.list_instances()

    def create_network(self):
        # Create network
        print("[*] Creating network")
        command = "./rack networks network create --name " + customer['internalNetworkName'] + self.postcommand  #+ " --region " + REGION
        resultsDict = json.loads(self.process_command(command)[0])
        self.networkID = resultsDict['ID']
        print("[+] Network ID: " + self.networkID)

    def add_subnet(self):
        # Add subnet
        print("[+] Creating subnet for network: " + self.networkID)
        command = "./rack networks subnet create --network-id " + self.networkID + " --name " + custID + "-SUBNET" + " --cidr " + customer['CIDR'] + " --gateway-ip " + customer['gateway'] + " --ip-version 4 --allocation-pool " + customer['allocationPool'] + " --dns-nameservers 8.8.8.8" + self.postcommand
        resultsDict = json.loads(self.process_command(command)[0])
        self.subnetID = resultsDict['ID']
        print("[+] Subnet ID: " + self.subnetID)

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
        
        elif not self.individualSSHkeys and os.path.isfile(keyName):
            print("[!] Key already exists locally: " + keyName)
            command = "./rack servers keypair upload --file " + keyName + ".pub" + " --name " + keyName + self.postcommand
            try:
                resultsDict = json.loads(self.process_command(command)[0])
            except:
                pass

        for srv in customer['servers']:
            if self.ansible:
                fh = open('ANSIBLE-PLAYBOOKS/' + srv['srvName'] + '.json', 'w')
            else:
                fh = open(srv['srvName'] + '.json', 'w')
            print("[*] Building server " + str(serverNum) + " / " + str(len(customer['servers'])))
            if self.individualSSHkeys:
                print("[*] Generating SSH key for: " + srv['srvName'])
                # SSH_KEY, no passphrase
                keyName = srv['srvName'] + "-SSHKEY"
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
            print("[+] Server ID: " + resultsDict['ID'])

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
            resultsDict['keyNamePub'] = keyName + '.pub'
            resultsDict['CIDR'] = customer['CIDR']
            resultsDict['internalNetworkName'] = customer['internalNetworkName']
            resultsDict['gateway'] = customer['gateway']
            resultsDict['allocationPool'] = customer['allocationPool']
            resultsDict['domain'] = customer['domain']
            resultsDict['ansibleRoles'] = srv['ansibleRoles']
            resultsDict['networkAndMask'] = customer['networkAndMask']  #self.expand_cidr(resultsDict['CIDR'])


            # Save dictionary to file for records and/or further processing
            fh.write(json.dumps(resultsDict, sort_keys=False, indent=4, separators=(',', ': ')) + '\n')
        
            serverNum += 1
    
            fh.close()
            #print(str(srv))

            if self.ansible:
                # Generate hosts file
                fh = open('ANSIBLE-PLAYBOOKS/hosts', 'a')
                fh.write('[' + srv['srvName'] + ']' + '\n')
                fh.write(resultsDict['PublicIPv4'] + ' ansible_ssh_private_key_file=' + resultsDict['KeyName'] + '\n'*2)
                fh.close()
                os.system('chmod -x ANSIBLE-PLAYBOOKS/hosts')

                # Place SSH keys in the right place
                os.system('mv ' + keyName +  ' ANSIBLE-PLAYBOOKS')
                os.system('mv ' + keyName + '.pub ' + ' ANSIBLE-PLAYBOOKS/ssh_keys/')

                #echo | python -c "import json;print json.load(open('123456-SRV1.json', 'r'))['PublicIPv4']" > PB-MAIN
                # Generate SSL certs
                if self.ssl:
                    print("[*] Generating a SSL certificate and key")                
                    os.system('openssl req -x509 -nodes -days 730 -sha256 -newkey rsa:2048 -keyout ANSIBLE-PLAYBOOKS/ssl/' + resultsDict['Name'] + '.key -out ANSIBLE-PLAYBOOKS/ssl/' + resultsDict['Name'] + '.crt -subj "/C=US/ST=Texas/L=San Antonio/O=PhishBarrel/OU=NA/CN=derp"')

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
            mask[i/8] = mask[i/8] + (1 << (7 - i % 8))

        netmask = ".".join(map(str, mask))

        # Initialize net and binary and netmask with addr to get network
        net = []
        for i in range(4):
            net.append(int(addr[i]) & mask[i])

        network = ".".join(map(str, net))

        return network + ' ' + netmask


    """def append_ansible_roles(self):
        # Append roles to ansible site.yml file    
        fh = open('ANSIBLE-PLAYBOOKS/site.yml', 'a')
        siteRoles= '''  roles:
    - common
    #- lamp
    #- ntp
    #- openvpn
    #- phpmyadmin
    #- pip
    #- PB-MAIN
    #- PB-RESEARCH
    #- PB-DB
    #- PB-WWW
    #- PN-ENFORCER
'''
        fh.write(siteRoles)
        fh.close()"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Rack Bob the Builder')
    parser.add_argument('-a', dest='ansible', action='store_true', default=False, help='Make preparations to pass variables to Ansible')
    parser.add_argument('-l', dest='ssl', action='store_true', default=False, help='Create individual SSL certificates and keys for each box')
    parser.add_argument('-s', dest='individualSSHkeys', action='store_true', default=False, help='Create individual SSH keys for each box (default is to create 1 for all boxes)')
    args = parser.parse_args()

    rb = RackBob(**vars(args))
    rb.build()
    print("[+] Done!")
