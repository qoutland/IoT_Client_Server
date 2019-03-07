import socket, sys, threading, socketserver, uuid, datetime, time, platform, os, hashlib
from threading import Thread

mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])
port = 9997
dev_id = 'dev1'
activityLog = 'Activity.log'
errorLog = 'Error.log'
passphrase = 'password'

#Flags are used to wait for an ACK
registered = False
loggedIn = False
regFlag = 0
regHash = hashlib.md5()
deregFlag = 0
deregHash = hashlib.md5()
loginFlag = 0
loginHash = hashlib.md5()
logoffFlag = 0
logoffHash = hashlib.md5()
dataFlag = 0
dataHash = hashlib.md5()

# function: start listener
def start_listener():
	# start thread for listener
	t2 = threading.Thread(target=UDP_listener)
	t2.daemon=True
	t2.start()

# function: receiver (listener)
def UDP_listener():

	# set socket for listener
	server = socketserver.UDPServer((ip, int(port)), MyUDPHandler)
	server.serve_forever()

# Class: MyUDPHandler (this receives all UDP messages)
class MyUDPHandler(socketserver.BaseRequestHandler):

	# interrupt handler for incoming messages
	def handle(self):
		global registered
		global loggedIn
		# parse received data
		data = self.request[0].strip()

		# set message and split
		message = data
		message = message.decode().split('\t')
		toLog('Message: ' + str(message) + ' was recieved.')
		if message[0] == 'ACK':
			if str(regHash) == str(message[4]):
				verifyReg(message)
			elif str(deregHash) == str(message[4]):
				verifyDereg(message)
			elif str(loginHash) == str(message[4]):
				verifyLogin(message)
			elif str(logoffHash) == str(message[4]):
				verifyLogoff(message)
			elif str(dataHash) == str(message[4]):
				verifyData(message)
			else:
				toLog('Bad hash: ' + str(message[4]))
		elif message[0] == 'QUE':
			handleQuery(message)
		else:			
			toError(message)

#Sends packets to the server
def send_packet(message):
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
		sock.sendto(message.encode(), (server_ip, int(server_port)))

#Used to register a device to the server 
def register():
	global regFlag
	global regHash
	mssg = 'REG\t' + dev_id + '\t' + passphrase + '\t' + str(mac) + '\t' + ip + '\t' + str(port)
	send_packet(mssg)
	regFlag = 1
	regHash = hashlib.md5(mssg.encode()).hexdigest()
	toLog('Sending register packet to: ' + str(server_ip)+ ':' + str(server_port))

#Verifies ACK packet for registration
def verifyReg(message):
	global regFlag
	global registered
	if message[1] =='00':
		regFlag = 0
		toLog('Successfully registered. ' + str(message))
		registered = True
	elif message[1] == '01':
		regFlag = 0
		toLog('Already registered. ' + str(message))
		registered = True
	elif message[1] == '02':
		regFlag = 0
		toLog('Already registered, just updated your IP. ' + str(message))
		registered = True
	elif message[1] == '12':
		regFlag = 0
		toLog('Reused IP Address.' + str(message))
	elif message[1] == '13':
		regFlag = 0
		toLog('Reused MAC Address. ' + str(message))

#Request to be deregistered from the server
def deregister():
	global deregFlag
	global deregHash
	mssg = 'DER\t' + dev_id + '\t' + passphrase + '\t' + str(mac) + '\t' + ip + '\t' + str(port)
	send_packet(mssg)
	deregFlag = 1
	deregHash = hashlib.md5(mssg.encode()).hexdigest()

#Verifies ACK packet for deregistration
def verifyDereg(message):
	global deregFlag
	global registered
	if message[1] == '20':
		deregFlag = 0
		toLog('Successfully deregistered. ' + str(message))
		registered = False
	elif message[1] == '21':
		deregFlag = 0
		toLog('Never registered. ' + str(message))
		registered = False
	elif message[1] == '30':
		deregFlag = 0
		toLog('Incorrect deregistration information. ' + str(message))

#Requests to login to the server
def login():
	global loginFlag
	global loginHash
	mssg = 'LIN\t' + dev_id + '\t' + passphrase + '\t' + ip + '\t' + str(port)
	send_packet(mssg)
	loginFlag = 1
	loginHash = hashlib.md5(mssg.encode()).hexdigest()

#Verifies ACK packet for logins
def verifyLogin(message):
	global loginFlag
	global loggedIn
	global registered
	if message[1] == '70':
		loginFlag = 0
		toLog('Successfully logged in' + str(message))
		loggedIn = True
		registered = True
	elif message[1] == '31':
		loginFlag = 0
		toLog('Need to register first.' + str(message))
		registered = False

#Requests to logoff of the server
def logoff():
	global logoffFlag
	global logoffHash
	mssg = 'LOF\t' + dev_id
	send_packet(mssg)
	logoffFlag = 1
	logoffHash = hashlib.md5(mssg.encode()).hexdigest()

#Verifies ACK packet for logoffs
def verifyLogoff(message):
	global logoffFlag
	global loggedIn
	if message[1] == '80':
		logoffFlag = 0
		toLog('Successfully logged off. ' + str(message))
		loggedIn = False

#Determines the data to send to th server
def handleQuery(message):
	if message[1] == '00':
		sendData('Test message')

#Send data to the server after being queued
def sendData(message):
	global dataHash
	mssg = 'DAT\t' + dev_id + '\t' + str(datetime.datetime.now()) + '\t' + str(len(message)) + '\t' + message
	send_packet(mssg)
	toLog('Sending data: ' + message)
	dataHash = hashlib.md5(mssg.encode()).hexdigest()

#Verifies ACK packet for data sent to the server
def verifyData(message):
	global dataFlag
	if message[1] == '50':
		dataFlag = 0
		toLog('Server successfully recieved data. ' + str(message))
	elif message[1] == '51':
		dataFlag = 0
		toLog('Device does not exist on this system.'  + str(message))

#Writes activity messages to a file (Updates in real time)
def toLog(message):
	log = open(activityLog, 'a')
	log.write(str(datetime.datetime.now()) + ': ' + message + '\n')
	log.close()

#Writes error messages to a file (Updates in real time)
def toError(message):
	log = open(errorLog, 'a')
	log.write(str(datetime.datetime.now()) + ': ' + message + '\n')
	log.close()

#Function used to get IP address
def getMyIP():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	ip = s.getsockname()[0]
	s.close()
	return str(s)

#Used to start the listener and server the menu
def main():
	global user_id
	global server_ip
	global server_port
	global ip

	if len(sys.argv) != 4:
		print("Usage: <program_file><user-ID><server-ip><server-port>")
		exit(1)
	user_id = sys.argv[1]
	server_ip = sys.argv[2]
	server_port = sys.argv[3]
	ip = getMyIP()
	start_listener()
	
	run = 1
	while(run):

		time.sleep(.1)
		os.system('cls') if platform.system() is 'Windows' else os.system('clear')
		print('\nSTATUS:\tRegistered: ' + str(registered) + '\tLogged in: ' + str(loggedIn) + '\n')
		print("Enter 'reg' to register this device.")
		print("Enter 'dereg' to deregister this devivce.")
		print("Enter 'login' to login to the server.")
		print("Enter 'logoff' to logoff of the server.")	
		print("Enter 'data' to send data to the server.")
		print("Enter 'quit' to end program")
		

		selection = input("Enter Selection: ")  
		if selection == 'reg':
			register()
		elif(selection == 'dereg'):
			deregister()
		elif(selection == 'login'):
			login()
		elif(selection == 'logoff'):
			logoff()
		elif(selection == 'data'):
			sendData(input('Enter the data would you like to send:'))
		elif(selection == 'quit'):
			run = 0

# initiate program
if __name__ == "__main__":
	#main(sys.argv)
	main()