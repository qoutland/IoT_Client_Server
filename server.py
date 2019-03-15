import socket, sys, threading, socketserver, datetime, platform, os, hashlib

class Client(object):
	def __init__(self, device_id, device_passw, device_mac, device_ip, device_port):
		self.id = device_id
		self.passw = device_passw
		self.mac = device_mac
		self.ip = device_ip
		self.port = device_port
		self.auth = False
		self.alive = True

	def updateIP(self, new_ip):
		self.ip = new_ip

	def updatePort(self, new_port):
		self.port = new_port

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

clients = []
activityLog = 'Activity.log'
errorLog = 'Error.log'
tstFlag = 0

# Starts TCP/UDP Listeners
def start_listener():
	t1 = threading.Thread(target=TCP_listener)
	t1.daemon=True
	t1.start()

# Self explanatory
def TCP_listener():
	global ip, port

	# set socket for listener
	server = socketserver.TCPServer((ip, int(port)), MyTCPHandler)
	server.serve_forever()

# Handles all incomping TCP Messages
class MyTCPHandler(socketserver.BaseRequestHandler):

	def handle(self):
		global port
		client_ip = self.client_address[0]
		data = self.request.recv(1024)
		message = data.decode().split('\t')
		toLog('Server Recieved: ' + str(message))

		if message[0] == 'REG':
			self.request.sendall(register(message, client_ip, data))
		elif message[0] == 'DER':
			self.request.sendall(deregister(message, client_ip, data))
		elif message[0] == 'LIN':
			self.request.sendall(login(message, client_ip, data))
		elif message[0] == 'LOF':
			self.request.sendall(logoff(message[1], data))
		elif message[0] == 'QUE':
			self.request.sendall(devQue(message))
		elif message[0] == 'DAT': 
			self.request.sendall(storeData(message, data))
		elif message[0] == 'ACK':
			verifyAck(message)
		else:			
			toError('Server: ' + str(message))

#Send TCP messages to clients
def send_tcp(mssg, client_ip, client_port):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((client_ip, int(client_port)))
		s.send(mssg.encode())
		toLog('Server Query: '+ str(mssg))
	except ConnectionRefusedError:
		toError('TCP Socket couldn\'t connect to: ' + str(client_ip) + ':' + str(client_port))
	finally:
		s.close()

#Performs integrity checks then registers client
def register(message, ip, data):
	global tstFlag
	code = ''
	for client in clients:
		#Already registered
		if (message[1] == client.id and message[2] == client.passw and message[3] == client.mac):
			if ip == client.ip:
				toLog('Client already registered.')
				code = '01'
				break
			else:
				toLog('Client already registered, just updated its IP.')
				client.updateIP(ip)
				code = '02'
				break
		#IP already registered
		elif ip == client.ip and tstFlag == 0:
			toLog('IP is already registered to another device.')
			code = '12'
			break
		#MAC already registered
		elif message[3] == client.mac and tstFlag == 0:
			toLog('MAC address is already registered to another device.')
			code = '20'
			break

	if code == '':
		toLog('Registering device: ' + message[1] )
		clients.append(Client(message[1], message[2], message[3], ip, '0'))
		code = '00'
		toLog('Device was successfully registered from message: ' + str(message))
	return ('ACK\t' + code + '\t' + message[1] + '\t' + str(datetime.datetime.now()) + '\t' + str(hashlib.md5(data).hexdigest())).encode()
	
#Performs integrity checks then deregisters client
def deregister(message, ip, data):
	code = ''
	for client in clients:
		if (message[1] == client.id and message[2] == client.passw and message[3] == client.mac):
			clients.remove(client)
			toLog('Device was successfully deregistered from message: ' + str(message))
			code = '20'
			break
		elif (message[1] == client.id or message[2] == client.mac):
			toLog('An device attempted to deregister with the wrong information: ' + str(message))
			code = '30'
			break

	if code == '':
		toLog('An unregistered device attempted to deregister: ' + str(message))
		code = '21'
	return ('ACK\t' + code + '\t' + message[1] + '\t' + str(datetime.datetime.now()) + '\t' + str(hashlib.md5(data).hexdigest())).encode()

#Handles client logins to the server
def login(message, ip, data):
	code = ''
	for client in clients:
		if (message[1] == client.id and message[2] == client.passw and ip == client.ip):
			client.updatePort(message[4])
			client.auth = True
			code = '70'
			break
	if code == '':
		code = '31'
	return ('ACK\t' + code + '\t' + message[1] + '\t' + str(datetime.datetime.now()) + '\t' + str(hashlib.md5(data).hexdigest())).encode()

#Handles client logoffs from the server
def logoff(dev_id, data):
	code = ''
	for client in clients:
		if (dev_id == client.id):
			if client.auth:
				client.auth = False
				code = '80'
				break
			else:
				code = '32'
				break

	if code == '':
		toLog('An unregistered device (' + dev_id + ') tried to logoff.')
		code = '31'
	return ('ACK\t' + code + '\t' + dev_id + '\t' + str(datetime.datetime.now()) + '\t' + str(hashlib.md5(data).hexdigest())).encode()

#Sends a query packet to a specific client
def sendQue():
	if len(clients) == 0:
		input('\nNo devices registered. Press ENTER to continue.')
		return 0
	else:
		show()
	client_dev_id = input('Enter the device ID: ')
	
	for client in clients:
		if str(client_dev_id) == client.id:
			if client.auth:
				pass
			else:
				input('Device must login first, press ENTER to continue.')
				return 0
		else:
			input('Device not found. Press ENTER to continue.')
			return 0

	code = input('What would you like to query for: ')

	for client in clients:
		if (client_dev_id == client.id):
			mssg = 'QUE\t' + str(code) + '\t' + str(client_dev_id) + '\t' + str(datetime.datetime.now())
			send_tcp(mssg, client.ip, client.port)
			return 0

#Responds a device IP and port to another client
def devQue(message):
	mssg = ''
	if message[1] == '01':
		for client in clients:
			if client.id == message[4]:
				if client.alive:
					ip_info = message[4] + '\t' + str(client.ip) + '\t' + str(client.port)
					return ('DAT\t01\t' + str(datetime.datetime.now()) + '\t' + str(len(ip_info)) + '\t' + ip_info).encode()
				else:
					return ('DAT\t12\t' + str(datetime.datetime.now()) + '\t1\t' + message[4]).encode()

		if mssg == '':
			toLog('Device with id: ' + message[4] + ' is not registerd')
			return ('DAT\t11\t' + str(datetime.datetime.now()) + '\t1\t' + message[4]).encode()
			
	else:
		toLog('Code not found: ' + str(message))
		return 0

#Stores data from clients
def storeData(message, data):
	code = ''
	for client in clients:
		if (message[2] == client.id):
			toLog('Stored the message: ' + str(message))
			code = '50'
	if code == '':
		toLog('Rejected the message(device not registered): ' + str(message))
		code = '51'
	return ('ACK\t' + code + '\t' + message[2] + '\t' + str(datetime.datetime.now()) + '\t' + str(hashlib.md5(data).hexdigest())).encode()

#Heartbeat to check if clients are alive
def heartbeat():
	if clients == '':
		toLog('No devices for heartbeat, will check again in 5 mins.')
		return 0
	else:
		for client in clients:
			if client.port != '0':
				toLog('Checking staus of ' + client.id + '.')
				mssg = 'STAT\t00\tserver\t' + str(datetime.datetime.now()) + '\t' + str(len('alive?')) + '\talive'
				client.alive = False
				send_tcp(mssg, client.ip, client.port)

#Verify ACKS
def verifyAck(message):
	if message[1] == '40':
		toLog(message[2] + ' is alive.')
		for client in clients:
			if message[2] == client.id:
				client.alive = True
	else:
		toError('Unkown ACK code: ' + message[1])

#Shows list of registerd clients
def show():
	os.system('cls') if platform.system() else os.system(clear)
	print('ID\t\tPass-phrase\tMAC\t\t\tIP\t\tPort\tLogged In\tOnline')
	for client in clients:
		print(client.id + '\t\t' +client.passw + '\t'+ client.mac + '\t' + client.ip + '\t' + client.port + '\t' + str(client.auth) + '\t\t' + str(client.alive))
	print('\n')

#Writes activity messages to a file (Updates in real time)
def toLog(message):
	log = open(activityLog, 'a')
	log.write(str(datetime.datetime.now()) + ': ' + message + '\n')
	log.close()

#Writes to error log
def toError(message):
	log = open(errorLog, 'a')
	log.write(str(datetime.datetime.now()) + ': ' + message + '\n')
	log.close()

#Starts listener and serves the menu
def main():
	
	global port
	global ip
	global tstFlag
	if len(sys.argv) < 2:
		print("Usage: <program_file><port>")
		exit(1)
	port = sys.argv[1]
	try:
		if sys.argv[2] == 'test':
			ip = '127.0.0.1'
			tstFlag = 1
	except:
		ip = socket.gethostbyname(socket.gethostname())

	start_listener() #Start TCP Listener
	beat = RepeatedTimer(300, heartbeat)#Start Heartbeat timer

	run = 1
	while(run):

		os.system('cls') if platform.system() is 'Windows' else os.system('clear')
		print("Enter 'show' to show all registered devices.")
		print("Enter 'query' to send data query to the client")
		print("Enter 'quit' to end program")

		selection = input("Enter Selection: ")
		if selection == 'show':
			show()
			input('Press Enter to Continue...')
		elif selection == 'query':
			sendQue()
		elif(selection == 'quit'):
			beat.stop()
			run = 0

if __name__ == "__main__":
	main()