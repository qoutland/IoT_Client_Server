import socket, sys, threading, socketserver, datetime, platform, os, hashlib

class Client(object):
	def __init__(self, device_id, device_passw, device_mac, device_ip, device_port):
		self.id = device_id
		self.passw = device_passw
		self.mac = device_mac
		self.ip = device_ip
		self.port = device_port
		self.auth = False

	def updateIP(new_ip):
		self.ip = new_ip

clients = []
activityLog = 'Activity.log'
errorLog = 'Error.log'
log = open(activityLog, 'a')
error = open(errorLog, 'a')

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
	global ip, port
	server = socketserver.UDPServer((ip, int(port)), MyUDPHandler)
	server.serve_forever()

# Self explanatory
def TCP_listener():
	global ip, port

	# set socket for listener
	server = socketserver.TCPServer((ip, int(port)), MyTCPHandler)
	server.serve_forever()

# Handles all incoming UDP Messages 
class MyUDPHandler(socketserver.BaseRequestHandler):

	def handle(self):

		data = self.request[0].strip()
		message = data.decode().split('\t')
		toLog('Message: ' + str(message) + ' was recieved.')
		
		if message[0] == 'REG':
			register(message[1], message[2], message[3], message[4], message[5], data)
		elif message[0] == 'DER':
			deregister(message[1], message[2], message[3], message[4], message[5], data)
		elif message[0] == 'LIN':
			login(message[1], message[2], message[3], message[4], data)
		elif message[0] == 'LOF':
			logoff(message[1], data)
		elif message[0] == 'DAT': 
			storeData(message[0], message[1], message[2], message[3], message[4], data)
		else:			
			toError(str(message))

# Handles all incomping TCP Messages
class MyTCPHandler(socketserver.BaseRequestHandler):

	def handle(self):
		global port
		client_ip = self.client_address[0]
		data = self.request.recv(1024)
		message = data.decode().split('\t')
		toLog('Server Message: ' + str(message) + ' was recieved.')

		if message[0] == 'REG':
			register(message[1], message[2], message[3], client_ip, port, data)
		elif message[0] == 'DER':
			deregister(message[1], message[2], message[3], client_ip, port, data)
		elif message[0] == 'LIN':
			login(message[1], message[2], client_ip, port, data)
		elif message[0] == 'LOF':
			logoff(message[1], str(message))
		elif message[0] == 'DAT': 
			storeData(message[0], message[1], message[2], message[3], message[4], data)
		else:			
			toError('Server: ' + str(message))

#Performs integrity checks then registers client
def register(dev_id, passw, mac, ip, port, message):
	for client in clients:
		#Already registered
		if (dev_id == client.id and passw == client.passw and mac == client.mac and port == client.port):
			if ip == client.ip:
				toLog('Client already registered.')
				send_tcp('01',dev_id, ip, port, message)
				return 0
			else:
				toLog('Client already registered, just updated its IP.')
				client.updateIP(ip)
				send_tcp('02',dev_id, ip, port, messsage)
				return 0
		#IP already registered
		elif ip == client.ip:
			toLog('IP is already registered to another device.')
			send_tcp('12',dev_id, ip, port, message)
			return 0
		#MAC already registered
		elif mac == client.mac:
			toLog('MAC address is already registered to another device.')
			send_tcp('20',dev_id, ip, port, message)
			return 0
	clients.append(Client(dev_id, passw, mac, ip, port))
	send_tcp('00', dev_id, ip, port, message)
	toLog('Device was successfully registered from message: ' + str(message))

#Performs integrity checks then deregisters client
def deregister(dev_id, passw, mac, ip, port, message):
	for client in clients:
		if (dev_id == client.id and passw == client.passw and mac == client.mac and port == client.port):
			clients.remove(client)
			send_tcp('20', dev_id, ip, port, message)
			toLog('Device was successfully deregistered from message: ' + str(message))
			return 0
		elif (dev_id == client.id or mac == client.mac or port == client.port):
			send_tcp('30', dev_id, ip, port, message)
			toLog('An device attempted to deregister with the wrong information: ' + str(message))

	send_tcp('21', dev_id, ip, port, message)
	toLog('An unregistered device attempted to deregister: ' + str(message))
	return 0

#Handles client logins to the server
def login(dev_id, passw, ip, port, message):
	for client in clients:
		if (dev_id == client.id and passw == client.passw and ip == client.ip  and port == client.port):
			client.auth = True
			send_tcp('70', dev_id, ip, port, message)
			return 0

	send_tcp('31', dev_id, ip, port, message)
	return 0

#Handles client logoffs from the server
def logoff(dev_id, message):
	for client in clients:
		if (dev_id == client.id):
			client.auth = False
			send_tcp('80',dev_id, client.ip, client.port, message)
			return 0

	#sendAck('31', dev_id, ip, port, message)
	toLog('An unauthorized device attempted to logoff another device: ' + str(message))
	return 0

#Sends UDP ACKS
def send_udp(code, dev_id, dest_ip, dest_port, message):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
	sock.sendto(('ACK\t' + code + '\t' + dev_id + '\t' + str(datetime.datetime.now()) + '\t' + str(hashlib.md5(message).hexdigest())).encode(), (dest_ip, int(dest_port)))

#Sends TCP ACKS
def send_tcp(code, dev_id, dest_ip, dest_port, message):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((dest_ip, int(dest_port)))
		s.send(('ACK\t' + code + '\t' + dev_id + '\t' + str(datetime.datetime.now()) + '\t' + str(hashlib.md5(message).hexdigest())).encode())
		s.close()
	except ConnectionRefusedError:
		toError('TCP Socket couldn\'t connect to: ' + str(dest_ip) + ':' + str(dest_port))

#Sends a query packet to a specific client
def sendQue():
	show()
	dev_id = input('Enter the device ID: ')
	code = input('What would you like to query for: ')

	for client in clients:
		if (dev_id == client.id):
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
			sock.sendto(('QUE\t' + str(code) + '\t' + dev_id + '\t' + str(datetime.datetime.now())).encode(), (client.ip, int(client.port)))
			return 0
	input('Device is not registered, press ENTER to continue...')

#Stores data from clients
def storeData(code, dev_id, time, length, data, message):
	for client in clients:
		if (dev_id == client.id):
			toLog('Stored the message: ' + str(data))
			send_tcp('50', dev_id, client.ip, client.port, message)
			return 0
	toLog('Rejected the message(device not registered): ' + str(data))
	send_tcp('51', dev_id, ip, port, message)

#Shows list of registerd clients
def show():
	os.system('cls') if platform.system() else os.system(clear)
	print('ID\t\tPass-phrase\t\tMAC\t\t\tIP\t\tPort\tLogged In')
	for client in clients:
		print(client.id + '\t\t' +client.passw + '\t\t'+ client.mac + '\t' + client.ip + '\t' + client.port + '\t' + str(client.auth) +'\n')
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
	if len(sys.argv) < 2:
		print("Usage: <program_file><port>")
		exit(1)
	port = sys.argv[1]
	try:
		if sys.argv[2] == 'test':
			ip = '127.0.0.1'
	except:
		ip = socket.gethostbyname(socket.gethostname())
	start_listener()
	
	run = 1
	while(run):

		#os.system('cls') if platform.system() is 'Windows' else os.system('clear')
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
			run = 0

if __name__ == "__main__":
	main()