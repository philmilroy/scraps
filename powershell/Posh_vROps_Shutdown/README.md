## Synopsis

vROps Powershell script to automate the process of restarting the vROps infrastructure, cluster and nodes

## Motivation

Currently no automated method to restart vROps that I could find. See the official release notes section: 'External shutdown affects cluster nodes' to understand why you should offline the cluster before shutdown/restarting

## Installation

Prerequisites:
-------------

- PowerCLI v6 or above
- Powershell v4 or above
- A Windows system to run the script from
- A 16 digit (no less, no more) encryption key. This can be made up but MUST be 16 characters in length
- Do NOT enter passwords into the XML manually - this process will be performed by the script with the exception of the encryption key which you can choose to enter or not
	- If you don't set the encryption key (insecurely) in the XML you will be prompted for it each time the script is run
	- If you do set the encryption key (insecurely) in the XML you should be able to schedule the script to run as an automated task

Notes:
-----

- Always use a DEVELOPMENT/SANDBOX environment for testing
- The REST calls use an UNDOCUMENTED API which is NOT SUPPORTED and may change at any time
	- Hopefully a documented API will take its place
- Please run through the install steps below and fill out the appropriate values for hostnames and usernames
- For the first run I suggest following the examples listed below
- Passwords
	- Passwords are requested at runtime IF THEY AREN'T ALREADY SET
	- Passwords can be removed by editing the XML and deleting the relevant SecureString entry/entries
		- If you remove a password you will be prompted for it again when you next run the script
	- Passwords are stored in Powershell SecureString format and the encryption key is used to decrypt them
	- If you don't set the encryption key in the script, you will be prompted for it each time you run the script
		- This means you cannot automate the process without setting the encryption key in the XML
		- This is NOT SECURE! With 2 lines of the right code you can decrypt all saved passwords. However, the only other conception I had would be to not use an encryption key. This would tie running the script to the user account that encrypted the passwords, which I decided was less friendly. I make the assumption that anyone with access to the configured script/XML will also have access to the required passwords, therefore the risk is mitigated
	- If you choose to only online/offline/restart the cluster, your vCenter password will not be prompted because it's not required for these operations
	- If you want to do a full node restart, you should set the XML appropriately with the nodes and then run the script manually the first time so it prompts for vCenter credentials
	- The encryption key needs to be 16 digits (no more or less) due to the way the encoding is performed
- Cluster operations
	- I had some issues bringing the cluster online which were resolved by adding a 30 second pause to the proceedings between the nodes coming online and when the cluster is brought online
	- During my efforts to resolve this I came up with 2 methods of bringing the cluster online/offline
		01) Using undocumented REST calls - this is the method being used
		02) Using a hidden IE instance - this worked but I needed to use some Start-Sleep commands to wait for IE and once I realised vROps just needed a little pause I went back to method 01
		- Both methods brought the cluster online, however, without the 30 second pause, the cluster would report FAILURE state until it was online
	- There are 9 choices of operations you can perform, only 1 of them should ever be set to true and the rest to false in the XML at one time. The script will throw an error if this is not the case
	- The choice of action you want to perform is determined by which of the 9 options is set to true in the XML
- Logging will be performed in the same directory that the script is run from and should include the same output that prints to the console when run manually
- Node shutdown and restart operations
	- The nodes are shutdown and restarted in a specific order as follows:
	- Shutdown
		- Data nodes
		- Replica node
		- Master node
	- Startup
		- Master node
		- Replica node
		- Data nodes

Installation instructions:
-------------------------

01) Ensure all prerequisites are met
02) Ensure you save the Powershell script and xml file in the same directory
03) Open the XML file with your favourite editor and fill in the following sections

	- scriptOperations - scriptOp # of the 9 available options, you should set 1 to true and ensure the others are set to false
		- The operation set to true in the XML will be the operation performed on the vROps cluster

	- vcenterMain
		- vchostname # Set the fqdn of your primary vCenter here - the vCenter where the vROps nodes live
		- username # Set the username for your vCenter login (must be able to shutdown/restart VM's)

	- vropsMain
		- username # Set the username for your vROPs login (must have full admin access to vROps)

	- mainNodes
		- masterNode - hostname # fqdn of the vROps Master node
		- replicaNode - hostname # fqdn of the vROps Replica node (if one exists). If none exist, do not enter any value
		- dataNodes - dNode - hostname # fqdn of the vROps Data node
			- Additional Data nodes may be added by including a full dNode tag along with the hostname sub-tag
			- The default XML has space for 2 Data nodes. If none exist, do not enter any values

	- remoteNodesGroup01vcenter
		- If no Data nodes exist here, do not enter any values
		- hostname # fqdn of the vCenter serving VM's from remoteNodesGroup01
		- username # username for the remoteNodesGroup01 vCenter

	- remoteNodesGroup01
		- rNode - hostname # fqdn of any Remote Collectors for remoteNodesGroup01
			- Additional Data nodes may be added by including a full rNode tag along with the hostname sub-tag
			- The default XML has space for 2 Data nodes. If none exist, do not enter any values

	- remoteNodesGroup02vcenter
		- hostname # fqdn of the vCenter serving VM's from remoteNodesGroup02
		- username # username for the remoteNodesGroup02 vCenter
			- Additional Data nodes may be added by including a full rNode tag along with the hostname sub-tag
			- The default XML has space for 2 Data nodes. If none exist, do not enter any values

	- remoteNodesGroup02
		- rNode - hostname # fqdn of any Remote Collectors for remoteNodesGroup02

	- vropsInsecureStorage - password # You may INSECURELY store the encryption key here to allow a fully automated script
		- Enter the 16 digit encryption key in plain text

04) Run the script in Powershell ISE and enter your encryption key
05) Depending on the operation selected, enter any requested passwords

Example Run to restart the vROps cluster:
----------------------------------------

	- Appliances
		- 1 x Master node
		- 1 x Replica node
		- 2 x 'main' Data nodes (configured as Remote Collectors)
		- 1 x vCenter hosting all nodes

01) Save .ps1 and XML into required folder
02) Open XML in editor
	- Modify scriptOp - clusterOp - Restart_Cluster - requested = true
		- All other scriptOp settings should already be set to false
	- Add vcenterMain fqdn
	- Add vcenterMain username (format: user@domain.com)
	- Add vropsMain username
	- Add masterNode fqdn
	- Add replicaNode fqdn
	- Add dNode fqdn for RC01
	- Add dNode fqdn for RC02
	(all my nodes are 'main' nodes so nothing in either remoteNodes groups)
	(technically I don't need to enter vCenter details because cluster restart only uses vROps but it will save time later)
	- Save XML
03) Run .ps1 in Powershell ISE
04) Enter a 16 digit encryption key. This can theoretically be anything you like but I haven't tested all combinations of special characters. I have tested a key of $$$$$$$$########
05) Enter a password for the vROps account (the password for username set in vropsMain - username)
06) (Cluster restart operation should begin)
07) Open XML in editor (optional)
	- Modify vropsInsecureStorage - password and enter the SAME encryption key you used during step 04
	- Save XML

Example Run to restart all nodes and bring cluster back online:
--------------------------------------------------------------

	- Prerequisite is to follow the example above first

01) Open XML in editor
	- Modify scriptOp - clusterOp - Restart_Cluster - requested = false
	- Modify scriptOp - clusterOp - Reboot_All_Nodes_Bring_Cluster_Online - requested = true
02) Run .ps1 in Powershell ISE
	- If encryption key was not entered into XML you will be prompted for it
03) Enter password for the vCenter account (the password for username set in vcenterMain username). Cluster offline will already be performed by the time you're prompted for this
04) Node shutdown and restart will commence
05) Cluster online will occur after all nodes have started successfully and a 30 second pause has elapsed

Approximate time taken to perform this operation = 20 minutes for a 4 node setup running on SSD's

Next steps:
----------

Assuming the XML was setup successfully and the script executed correctly in Powershell ISE there's no reason you can't set this up as a scheduled task to run during a maintenance window

## Testing

I have tested all operations concerning 'main' nodes using the setup in the example above. I don't have enough kit to spin up additional vCenters and fully test the remoteNodes groups as the vROps footprint is pretty horrific

## License and Warranty

No license or warranty are implied. This script is provided "as-is", use at your own risk. Always use a DEVELOPMENT/SANDBOX environment for testing