# Iot_Client_Server

This application simulates communication between a IoT Server and Client via TCP comunication.
Clients are also able to talk to eachother via UDP communication. Activities are logged in Activity.log and Errors are logged in Error.log.

To run on a localhost run both the client and server with the test argument at the end of the command.

## Server

Run instructions:

```bash
python server.py server_port *test*
```

### Usage 

```
show: Shows all devices registered to the server
query: Send a query to a specified device for data
quit: Terminate the program
```

## Client

Run Instructions:

```bash
python client.py device_id server_ip server_port *test*
```

### Usage

```
show: Shows list of devices known to this client
reg: Registers a device to the server specified in command line arg
dereg: Deregisters the server
login: Sends login information to the server
logoff: Sends logout information to the server
query: Query another device for info
data: Send data to the server
quit: Terminate the program
```