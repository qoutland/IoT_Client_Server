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
show: Shows all clients registered to the server
query: Query a client for data
share: Share information via email
quit: Terminate the program
```

## Client

Run Instructions:

```bash
python client.py device_id server_ip server_port *test*
```

### Usage

```
show: Shows list of clients known to this client
reg: Registers the client to the server
dereg: Deregisters the client from the server
login: Log the client into the server
logoff: Log a client off of the server
query: Query another client for info
data: Send data to the server
quit: Terminate the program
```

## Cloud Implementation

Both the client and the server take advantage of dropbox cloud storage.
    - The clients sync data any time they have any to write to the cloud
    - The server polls the cloud every 5 minutes for new data
To use add API_KEY to  *apikey.py* in the format of the sameple_key.py.

## Sharing and Security
The server can send an email to other users to share data with them.

Client/Server and Client/Client authentication is done using private and public keys.

To use add USER_EMAIL and USER_EMAIL_PASSWORD to  *apikey.py* in the format of the sameple_key.py.