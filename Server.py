import socket
from threading import Thread
from datetime import datetime

# Multithreaded Python server : TCP Server Socket Thread Pool
class ClientThread(Thread):
    def __init__(self, ip, port):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.msgCount = 0
        print("[+] New server socket thread started for " + ip + ":" + str(port))

    def run(self):
        while True:
            data = conn.recv(2048)
            now = datetime.now()
            current_time = now.strftime("%H:%M:%S")
            print("Server received data:" + str(self.msgCount) + ":" + str(data) + ":" + current_time)
            print()
            #MESSAGE = input("Server : Enter Response from Server/Enter exit:")
            MESSAGE = "Server received your message number " + str(self.msgCount)
            MESSAGE_BYTES = bytes(MESSAGE, 'utf-8')
            conn.send(MESSAGE_BYTES)  # echo message to client
            if data == b'exit':
                break
            self.msgCount += 1

# Multithreaded Python server : TCP Server Socket Program Stub
TCP_IP = '0.0.0.0'  #server will listen for and accept connections from any IP address
TCP_PORT = 2004     #server port hardcoded for now
#BUFFER_SIZE = 20  # Usually 1024, but we need quick response

tcpServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcpServer.bind((TCP_IP, TCP_PORT))
threads = []

while True:
    tcpServer.listen(4)  # 4 unaccepted connections that the system will allow before refusing new connections.
    print("Server : Waiting for connections from TCP clients...")
    (conn, (ip, port)) = tcpServer.accept()
    newthread = ClientThread(ip, port)
    newthread.start()
    threads.append(newthread)

#for t in threads:
#    t.join()
