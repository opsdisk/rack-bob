#### Motivation
Short for Rackspace bob-the-builder, this script builds servers with Rackspace's `rack` binary [https://github.com/rackspace/rack]([https://github.com/rackspace/rack). The goal of the project was to combine a number of DevOps concepts I've been learning lately.

1. Minimize building servers by hand/GUI and treat infrastructure-as-code by utilizing an API.  Other cloud providers, like Digital Ocean, also provide this feature with their API [https://developers.digitalocean.com/](https://developers.digitalocean.com/)

2. Minimize hand off to Ansible which will configure the servers based on pre-defined playbooks.  Ansible allows you to logically configure servers.

In plain English, this can be described as:
    
    I want to build a Ubuntu server with 2 CPUs and 4 GB of memory in Dallas, use this SSH key and this root password, and add an additional NIC with an IP address of 10.10.20.2.  When that's done, harden the OS, the SSH server, update the .bash_aliases file, and install Apache web server.

My old workflow consisted of:

* Using a web GUI to pick the hardware specifications
* SSH'ing in and copying/pasting a BASH type of file to configure the server based on role

`rack-bob.py` cuts down the manual spin up and configuration time from minutes to seconds.  This solution was custom for me, but hopefully others can utilize it for their needs.

#### Overview
`rack-bob.py` is a Python wrapper that builds servers in a specific order.  I had issues with `pyrax` and `python-novaclient` libraries and their dependencies and the `rack` binary just worked out of the box. The script allows SSH key injection, root password injection, and internal network configuration (IPs are assigned in the order they are built).  The internal network configuration allows one to add an additional NIC to allow communication on a private subnet.  For example, you could spin up a web server (with a public and private IP) and database server (with only a private IP).  The web server only communicates with the database server over the private IP.

It also writes a .json file to disk complete with all the server details.  Sensitive info has been replaces with `X`'s and `Y`'s.

```
{
    "domain": "example.com",
    "flavorName": "8 GB General Purpose v1",
    "rootPassHash": "$6$rounds=40000$3CsKE8qCEwC4huI9$RVh0284e2.iAG69KN9FoA/luUC6GpaFgBizjVJzMU.V7VM3YKc82q10pbbQjtFF6iOLJdSrC.fWDi2Php3sv5/",
    "Progress": 100,
    "gateway": "10.10.20.1",
    "Metadata": {},
    "Status": "ACTIVE",
    "Updated": "2016-01-07T05:48:42Z",
    "networkAndMask": "10.10.20.0 255.255.255.0",
    "TenantID": "XXXXXX",
    "allocationPool": "start=10.10.20.2,end=10.10.20.254",
    "imageName": "Ubuntu 14.04 LTS (Trusty Tahr) (PVHVM)",
    "SecurityGroups": null,
    "keyNamePub": "123456-SSHKEY.pub",
    "rootPass": "07lmmrP2F7bnOf0HnkP",
    "PublicIPv4": "104.239.XX.YY",
    "Name": "123456-WWW",
    "PublicIPv6": "2001:4800:7820:101:be76:4eff:XXXX:YYYY",
    "Created": "2016-01-07T05:48:19Z",
    "KeyName": "123456-SSHKEY",
    "PrivateIPv4": "10.10.20.2",
    "CIDR": "10.10.20.0/24",
    "ID": "0221dee5-c9df-4550-XXXXX-4cf134cYYYY",
    "ansibleRoles": [
        "common",
        "WWW"
    ],
    "Image": "09de0a66-3156-48b4-90a5-1cf25a905207",
    "internalNetworkName": "123456-INTERNAL-NETWORK",
    "Flavor": "general1-8",
    "region": "DFW"
}
```

#### Switches
```
usage: rack_bob.py [-h] [-a] [-c CONFIGFILE] [-l] [-p PREFIXID] [-s]

Rack Bob the Builder

optional arguments:
  -h, --help     show this help message and exit
  -a             Make preparations to pass variables to Ansible
  -c CONFIGFILE  .json configuration file to read in with server details
  -l             Create individual SSL certificates and keys for each box
  -p PREFIXID    Server prefix ID (e.g., customer ID, Account number), default
                 is 123456
  -s             Create individual SSH keys for each box (default is to create
                 1 for all boxes)

```
* Read server build configuration information from a .json file with `-c` switch. Otherwise, a global dictionary is used.

* Make preparations for a post-Ansible deployment with the `-a` switch.  This switch also places SSH/SSL keys in the correct location and creates the `hosts` and `site.yml` files for a streamlined Ansible configuration and deployment. 

* Create individual SSL certificates for servers if they are need with `-l` switch

* Prefix a customer/account ID to distinguish servers, networks, and subnets with the `-p` switch

* Create individual passphrase-less SSH keys for each server with the `-s` switch

#### servers.json
Example file
```
{   
    "internalNetworkName": "INTERNAL-NETWORK",
    "CIDR": "10.10.20.0/24",
    "networkAndMask": "10.10.20.0 255.255.255.0",
    "gateway": "10.10.20.1",
    "allocationPool": "start=10.10.20.2,end=10.10.20.254",
    "domain": "example.com",
    "servers": [
                    {
                       "region": "DFW",
                       "srvName": "WWW",
                       "imageName": "Ubuntu 14.04 LTS (Trusty Tahr) (PVHVM)",
                       "flavorName": "2 GB General Purpose v1",
                       "ansibleRoles": ["common", "WWW"]
                    },
               ]
}
```

#### Future Work
There is a lot more to learn in the automation and DevOps world, and I'm sure this is not the most efficient or simplest way to do things...it will likely be a work in progress.  All of the code can be found on the Opsdisk Github repository here: https://github.com/opsdisk/rack-bob.  Comments, suggestions, and improvements are always welcome.  Be sure to follow [@opsdisk](https://twitter.com/opsdisk) on Twitter for the latest updates. 