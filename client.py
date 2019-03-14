import socket, sys, threading, socketserver, uuid, datetime, time, platform, os, hashlib

class Client(object):
	def __init__(self, device_id, device_ip, device_port):
		self.id = device_id
		self.ip = device_ip
		self.port = device_port
		self.alive = False

clients = []

mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])
port = 9997
activityLog = 'Activity.log'
errorLog = 'Error.log'
passphrase = 'password'
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

# Starts TCP/UDP Listeners
def start_listener():
	t1 = threading.Thread(target=TCP_listener)
	t1.daemon=True
	t1.start()
	t2 = threading.Thread(target=UDP_listener)
	t2.daemon=True
	t2.start()

# Self explanatory
def UDP_listener():
	global ip, port, udp_server
	udp_server = socketserver.UDPServer((ip, int(port)), MyUDPHandler)
	udp_server.serve_forever()

# Self explanatory
def TCP_listener():
	global ip, port, tcp_server
	tcp_server = socketserver.TCPServer((ip, int(port)), MyTCPHandler)
	#PROD #server = socketserver.TCPServer((ip, int(server_port)), MyTCPHandler)
	tcp_server.serve_forever()

# Recieves all TCP Messages
class MyTCPHandler(socketserver.BaseRequestHandler):

	def handle(self):
		global registered
		global loggedIn

		data = self.request.recv(1024)
		message = data.decode().split('\t')
		toLog('Client Message: ' + str(message) + ' was recieved.')

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
		elif message[0] == 'DAT':
			receieveMssg(message)
		elif message[0] == 'QUE':
			handleQuery(message)
		else:			
			toError(message)

# Recieves all UDP Messsages
class MyUDPHandler(socketserver.BaseRequestHandler):

	def handle(self):
		global registered
		global loggedIn

		data = self.request[0].strip()
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
def send_udp(message):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
	sock.sendto(message.encode(), (server_ip, int(server_port)))

#Sends packets to the server
def send_tcp(message):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind(('', int(port)))
		s.connect((server_ip, int(server_port)))
		s.send(message.encode())
		data = s.recv(1024)
		message = data.decode().split('\t')
	except ConnectionRefusedError:
		toError('TCP Socket couldn\'t connect to: ' + str(server_ip) + ':' + str(server_port))
	finally:
		s.close()
		toLog('Client Recieved: ' + str(message))
		return message

#Used to register a device to the server 
def register():
	global regFlag
	global regHash
	#UDP #mssg = 'REG\t' + dev_id + '\t' + passphrase + '\t' + str(mac) + '\t' + ip + '\t' + str(port)
	#UDP #send_udp(mssg)
	mssg = 'REG\t' + dev_id + '\t' + passphrase + '\t' + str(mac)
	regFlag = 1
	regHash = hashlib.md5(mssg.encode()).hexdigest()
	toLog('Sending register packet to: ' + str(server_ip)+ ':' + str(server_port))
	verifyReg(send_tcp(mssg))

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
	mssg = 'DER\t' + dev_id + '\t' + passphrase + '\t' + str(mac)
	deregFlag = 1
	deregHash = hashlib.md5(mssg.encode()).hexdigest()
	verifyDereg(send_tcp(mssg))

#Verifies ACK packet for deregistration
def verifyDereg(message):
	global deregFlag
	global registered
	if str(message[1]) == '20':
		deregFlag = 0
		toLog('Successfully deregistered. ' + str(message))
		registered = False
	elif str(message[1]) == '21':
		deregFlag = 0
		toLog('Never registered. ' + str(message))
		registered = False
	elif str(message[1]) == '30':
		deregFlag = 0
		toLog('Incorrect deregistration information. ' + str(message))

#Requests to login to the server
def login():
	global loginFlag
	global loginHash
	mssg = 'LIN\t' + dev_id + '\t' + passphrase
	loginFlag = 1
	loginHash = hashlib.md5(mssg.encode()).hexdigest()
	verifyLogin(send_tcp(mssg))

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
	logoffFlag = 1
	logoffHash = hashlib.md5(mssg.encode()).hexdigest()
	verifyLogoff(send_tcp(mssg))

#Verifies ACK packet for logoffs
def verifyLogoff(message):
	global logoffFlag
	global loggedIn
	if message[1] == '80':
		logoffFlag = 0
		toLog('Successfully logged off. ' + str(message))
		loggedIn = False
	elif message[1] == '31':
		logoffFlag = 0
		toLog('Need to register first. ' + str(message))
		loggedIn = False
	elif message[1] == '32':
		logoffFlag = 0
		toLog('Device was never logged on. ' + str(message))
		loggedIn = False

#Determines the data to send to th server
def handleQuery(message):
	if message[1] == '00':
		sendData('Test message')

#Queries server for device information
def queryID():
	que_dev_id = input('Enter the device id you want to query: ')
	send_tcp('QUE\t01\t' + dev_id + '\t' + str(datetime.datetime.now()) + '\t' + str(que_dev_id))

#Some kind of comment here
#def query():

def receieveMssg(message):
	if message[1] == '01':
		clients.append(Client(message[5], message[6], message[7]))
		toLog('Added ' + message[5] + 'to client list.')
	elif message[1] == '11':
		toLog('No entry found for: ' + message[5])
	elif message[1] == '12':
		toLog('Device' + message[5] + 'is not currently online')
	else:
		toLog('Qcode: ' + message[1] + ' not found.')

#Send data to the server after being queued
def sendData(message):
	global dataHash
	mssg = 'DAT\t' + dev_id + '\t' + str(datetime.datetime.now()) + '\t' + str(len(message)) + '\t' + message
	send_tcp(mssg)
	toLog('Sending data: ' + mssg)
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

def show():
	os.system('cls') if platform.system() else os.system(clear)
	print('ID\t\tIP\t\tPort\tAlive')
	for client in clients:
		print(client.id + '\t' + client.ip + '\t' + client.port + '\t' + str(client.alive) +'\n')
	print('\n')

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

#Used to start the listener and server the menu
def main():
	global dev_id
	global server_ip
	global server_port
	global ip
	global port

	if len(sys.argv) < 4:
		print("Usage: <program_file><device-ID><server-ip><server-port>")
		exit(1)

	dev_id = sys.argv[1]
	server_ip = sys.argv[2]
	server_port = sys.argv[3]
	port = sys.argv[3]
	try:
		if sys.argv[4] == 'test':
			ip = '127.0.0.1'
			port = 9998
	except:
		ip = socket.gethostbyname(socket.gethostname())
	start_listener()
	
	run = 1
	while(run):

		time.sleep(.1)
		os.system('cls') if platform.system() is 'Windows' else os.system('clear')
		print('\nSTATUS:\tRegistered: ' + str(registered) + '\tLogged in: ' + str(loggedIn) + '\n')
		print("Enter 'show' to show other devices.")
		print("Enter 'reg' to register this device.")
		print("Enter 'dereg' to deregister this devivce.")
		print("Enter 'login' to login to the server.")
		print("Enter 'logoff' to logoff of the server.")
		print("Enter 'server_query' to query the server.")
		print("Enter 'device_query' to query another device.")
		print("Enter 'data' to send data to the server.")
		print("Enter 'quit' to end program")
		
		selection = input("Enter Selection: ")
		if selection == 'show':
			show()
			input('Press Enter to Continue...')
		elif selection == 'reg':
			register()
		elif selection == 'dereg':
			deregister()
		elif selection == 'login':
			login()
		elif selection == 'logoff':
			logoff()
		elif selection == 'server_query':
			queryID()
		elif selection == 'device_query':
			print('Not done yet')
		elif selection == 'data':
			sendData(input('Enter the data would you like to send:'))
		elif selection == 'quit':
			run = 0

if __name__ == "__main__":
	main()