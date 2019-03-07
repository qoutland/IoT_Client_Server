# Iot_Client_Server

This application is used to simulate IoT communication between computers

## Client

Run instructions:

'''bash
python client.py user_id server_ip server_port
'''

### Usage
reg: Registers a device to the server specified in command line arg
dereg: Deregisters the server
login: Sends login information to the server
logoff: Sends logout information to the server
data: Send data to the server
quit: Terminate the program

## Server 

Run instructions:

'''bash
python server.py server_port
'''

### Usage

query: Send a query to a specified device for data
quit: Terminate the program
