import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

BUFFER_SIZE = 2000
MESSAGE = ""

tcpClient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpClient.connect((host, port))

while MESSAGE != 'exit':
    MESSAGE = input("Client: Enter message to continue/ Enter exit:")
    MESSAGE_BYTES = bytes(MESSAGE, 'utf-8')
    tcpClient.send(MESSAGE_BYTES)
    data = tcpClient.recv(BUFFER_SIZE)
    print("Client received data:", str(data))

print("Client Terminating")
tcpClient.close()
                   