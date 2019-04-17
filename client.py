import socket, sys, threading, socketserver, uuid, datetime, time, platform, os, hashlib, dropbox

#Class for adding clients to my list
class Client(object):
	def __init__(self, device_id, device_ip, device_port):
		self.id = device_id
		self.ip = device_ip
		self.port = device_port
		self.alive = True

	def updateNet(self, client_ip, client_port):
		self.ip = client_ip
		self.port  = client_port

#Got this from stack overflow, works good
class RepeatedTimer(object):
    def __init__(self, interval, function):
        self._timer     = None
        self.interval   = interval
        self.function   = function
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function()

    def start(self):
        if not self.is_running:
            self._timer = threading.Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False

#Global vars
clients = []
mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])
activityLog = 'Activity.log'
errorLog = 'Error.log'
passphrase = 'password'
registered = False
loggedIn = False
API_KEY = 0
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
		toLog('Client Recieved: ' + str(message))

		if message[0] == 'QUE':
			handleQuery(message, 1)
		elif message[0] == 'ACK':
			handleAck(message)
		elif message[0] == 'STAT':
			verifyBeat(message, 1)
		else:			
			toError(str(message))

# Recieves all UDP Messsages
class MyUDPHandler(socketserver.BaseRequestHandler):

	def handle(self):
		global registered
		global loggedIn

		data = self.request[0].strip()
		message = data
		message = message.decode().split('\t')
		toLog('Client recieved: ' + str(message))

		if message[0] == 'QUE':
			handleQuery(message, 0)
		elif message[0] == 'DAT':
			storeData(message)
		elif message[0] == 'STAT':
			verifyBeat(message, 0)
		elif message[0] == 'ACK':
			handleAck(message)
		else:			
			toError(message)

#Sends packets to the server
def send_udp(message, client_ip, client_port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
	sock.sendto(message.encode(), (client_ip, int(client_port)))

#Sends packets to the server
def send_tcp(message):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(10)
		s.bind(('', int(port)))
		s.connect((server_ip, int(server_port)))
		s.send(message.encode())
		data = s.recv(1024)
		mssg = data.decode().split('\t')
	except ConnectionRefusedError:
		toError('TCP Socket couldn\'t connect to: ' + str(server_ip) + ':' + str(server_port))
	finally:
		s.close()
		try:
			toLog('Client Recieved: ' + str(mssg))
			return mssg
		except:
			toLog('Client could not connect to server: '+ str(server_ip) + ':' + str(server_port))
			return 0

#Used to register a device to the server 
def register():
	global regHash
	mssg = 'REG\t' + dev_id + '\t' + passphrase + '\t' + str(mac)
	regHash = hashlib.md5(mssg.encode()).hexdigest()
	toLog('Sending register packet to: ' + str(server_ip)+ ':' + str(server_port))
	for i in range(0,3):
		resp = send_tcp(mssg)
		if resp == 0:
			toError('Unable to connect to server on try:' +str(i+1))
			pass
		else:
			verifyReg(resp)
			break

#Verifies ACK packet for registration
def verifyReg(message):
	global registered
	global regHash
	global dbx
	global API_KEY
	if regHash == message[5]:
		if message[1] =='00':
			toLog('Successfully registered. ' + str(message))
			registered = True
			if message[3] != '0':
				API_KEY = message[3]
				dbx = dropbox.Dropbox(API_KEY)
		elif message[1] == '01':
			toLog('Already registered. ' + str(message))
			registered = True
		elif message[1] == '02':
			toLog('Already registered, just updated your IP. ' + str(message))
			registered = True
		elif message[1] == '12':
			toLog('Reused IP Address.' + str(message))
		elif message[1] == '13':
			toLog('Reused MAC Address. ' + str(message))

	else:
		toError('Invalid register hash: ' + message[4] + ' != ' + regHash )

#Request to be deregistered from the server
def deregister():
	global deregHash
	mssg = 'DER\t' + dev_id + '\t' + passphrase + '\t' + str(mac)
	deregHash = hashlib.md5(mssg.encode()).hexdigest()
	toLog('Sending deregister packet to: ' + str(server_ip)+ ':' + str(server_port))
	verifyDereg(send_tcp(mssg))

#Verifies ACK packet for deregistration
def verifyDereg(message):
	global registered
	global deregHash
	if deregHash == message[4]:
		if message[1] == '20':
			toLog('Successfully deregistered. ' + str(message))
			registered = False
		elif message[1] == '21':
			toLog('Never registered. ' + str(message))
			registered = False
		elif message[1] == '30':
			toLog('Incorrect deregistration information. ' + str(message))
	else:
		toError('Invalid deregister hash: ' + message[4] + ' != ' + regHash )

#Requests to login to the server
def login():
	global loginHash
	mssg = 'LIN\t' + dev_id + '\t' + passphrase + '\t' + ip + '\t' + str(port)
	loginHash = hashlib.md5(mssg.encode()).hexdigest()
	toLog('Sending login packet to: ' + str(server_ip)+ ':' + str(server_port))
	verifyLogin(send_tcp(mssg))

#Verifies ACK packet for logins
def verifyLogin(message):
	global loggedIn
	global registered
	global loginHash
	if loginHash == message[4]:
		if message[1] == '70':
			toLog('Successfully logged in' + str(message))
			loggedIn = True
			registered = True
		elif message[1] == '31':
			toLog('Need to register first.' + str(message))
			registered = False
	else:
		toError('Invalid login hash: ' + message[4] + ' != ' + loginHash )

#Requests to logoff of the server
def logoff():
	global logoffHash
	mssg = 'LOF\t' + dev_id
	logoffHash = hashlib.md5(mssg.encode()).hexdigest()
	toLog('Sending logoff packet to: ' + str(server_ip)+ ':' + str(server_port))
	verifyLogoff(send_tcp(mssg))

#Verifies ACK packet for logoffs
def verifyLogoff(message):
	global loggedIn
	global logoffHash
	if logoffHash == message[4]:
		if message[1] == '80':
			toLog('Successfully logged off. ' + str(message))
			loggedIn = False
		elif message[1] == '31':
			toLog('Need to register first. ' + str(message))
			loggedIn = False
		elif message[1] == '32':
			toLog('Device was never logged on. ' + str(message))
			loggedIn = False
	else:
		toError('Invalid logoff hash: ' + message[4] + ' != ' + logoffHash )

#Determines the data to send to th server
def handleQuery(message, server):
	if message[1] == '00':
		mssg = 'DAT\t00\t' + dev_id + '\t' + str(datetime.datetime.now()) + '\t' + str(len('Test message')) +'\t' + 'Test message'
	else:
		toError('Query code: ' + message[1] + 'is not recognized.')
	if server:
		handleAck(send_tcp(mssg))
		toCloud()
	else:
		queryID(message[2])
		for client in clients:
			if message[2] == client.id:
				if message[1] == '00':
					send_udp(mssg, client.ip, client.port)
					return 0
				else:
					toError('Invalid query code: ' + message[1])
					return 0
		toError('Recieved message from unregistered/unknown device')
	return 0

#Handles Client Acknowlegdments
def handleAck(message):
	if message[1] == '40':
		toLog(message[2] + ' is alive.')
		for client in clients:
			if message[2] == client.id:
				client.alive = True
	elif message[1] == '50':
		toLog('Client/Server successfully recieved data message') 

#Queries server for device information
def queryID(device_id):
	toLog('Querying server for: ' + device_id)
	addClient(send_tcp('QUE\t01\t' + dev_id + '\t' + str(datetime.datetime.now()) + '\t' + str(device_id)))

#Adds to the Clients list of clients
def addClient(message):
	if message[1] == '01':
		for client in clients:
			if (message[4] == client.id):
				if (message[5] == client.ip and message[6] == client.port):
					toLog('Client ' + message[4] + ' already added.')
					return 0
				else:
					toLog('Updating ' + message[4] + '.')
					client.updateNet(message[5], message[6])
					return 0
		clients.append(Client(message[4], message[5], message[6]))
		toLog('Added new client.' + str(message))
	elif message[1] == '11':
		toLog('No entry found for: ' + message[4])
	elif message[1] == '12':
		toLog('Device' + message[4] + 'is not currently online')
	else:
		toLog('Qcode: ' + message[1] + ' not found.')

#Query other devices
def query():
	global dev_id
	show()
	client_dev_id = input('Enter the device ID (From above or query the server for a new one): ')
	if client_dev_id != dev_id:
		queryID(client_dev_id)
	else:
		input('Cannot query self. Press ENTER to continue.')
		return 0

	for client in clients:
		if client_dev_id == client.id:
			code = input('What would you like to query for: ')
			mssg = 'QUE\t' + str(code) + '\t' + dev_id + '\t' + str(datetime.datetime.now())
			send_udp(mssg, client.ip, client.port)
			toLog('Client Que: '+ str(mssg))
			return 0
	input('Device not found. Press ENTER to continue.')
	return 0

#Send data to the server after being queued
def sendData(message):
	global dataHash
	mssg = 'DAT\t11\t' + dev_id + '\t' + str(datetime.datetime.now()) + '\t' + str(len(message)) + '\t' + message
	toLog('Sending data: ' + mssg)
	toCloud(message)
	handleAck(send_tcp(mssg))

	dataHash = hashlib.md5(mssg.encode()).hexdigest()

#Recieves data from device after query
def storeData(message):
	toLog('Storing: ' + message[5])
	for client in clients:
		if message[2] == client.id:
			send_udp('ACK\t50\t' + dev_id + '\t' + str(datetime.datetime.now()) + '\t' + str(hashlib.md5(str(message).encode()).hexdigest()), client.ip, client.port)

#Verifies ACK packet for data sent to the server
def verifyData(message):
	if message[1] == '50':
		toLog('Server successfully recieved data. ' + str(message))
	elif message[1] == '51':
		toLog('Device does not exist on this system.'  + str(message))

#Function to check if another client is still alive
def heartbeat():
	if clients == '':
		toLog('No devices for heartbeat, will check again in 5 mins.')
		return 0
	else:
		for client in clients:
			toLog('Checking staus of ' + client.id + '.')
			mssg = 'STAT\t00\t' + dev_id + '\t' + str(datetime.datetime.now()) + '\t' + str(len('alive?')) + '\talive'
			client.alive = False
			send_udp(mssg, client.ip, client.port)
			
#Sends ACK to verify that I am alive
def verifyBeat(message, server):
	if server:
		toLog('Telling the server I am alive.')
		send_tcp('ACK\t40\t' + dev_id + '\t' + str(datetime.datetime.now()) + '\t' + str(hashlib.md5(str(message).encode()).hexdigest()))
		return 0

	queryID(message[2])
	for client in clients:
		if client.id == str(message[2]):
			toLog('Telling '+ client.id + ' I am alive.')
			send_udp('ACK\t40\t' + dev_id + '\t' + str(datetime.datetime.now()) + '\t' + str(hashlib.md5(str(message).encode()).hexdigest()), client.ip, client.port)
			return 0
	toLog('Could not find device: ' + message[2])

#Prints list of stored devices
def show():
	os.system('cls') if platform.system() else os.system(clear)
	print('ID\t\tIP\t\tPort\tAlive')
	for client in clients:
		print(client.id + '\t\t' + client.ip + '\t' + client.port + '\t' + str(client.alive) +'\n')
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

#Send data to the cloud
def toCloud(message):
	if API_KEY != 0:
		#If it exists download it
		if 'dev1' in dbx.files_list_folder('').entries:
			dbx.files.DownloadArg(path='/'+dev_id+'.txt')
		f=open(str(dev_id)+'.txt', 'a+')
		f.write(message[5])
		f.close()
		with open(str(dev_id)+'.txt', 'rb') as f:
			dbx.files_upload(f.read(), '/', dropbox.files.WriteMode.overwrite)
		f.close()

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
			port = 9997
	except:
		ip = socket.gethostbyname(socket.gethostname())

	start_listener()#Start UDP/TCP Listening threads
	beat = RepeatedTimer(300, heartbeat)#Start Heartbeat timer

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
		print("Enter 'query' to query another device.")
		print("Enter 'data' to send data to the server.")
		print("Enter 'quit' to end program.")
		
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
		elif selection == 'query':
			query()
		elif selection == 'data':
			sendData(input('Enter the data would you like to send:'))
		elif selection == 'quit':
			beat.stop()
			run = 0

if __name__ == "__main__":
	main()