import socket
from threading import Thread
from datetime import datetime

class ClientThread(Thread):
    def __init__(self, conn, ip, port):
        Thread.__init__(self)
        self.conn = conn
        self.ip = ip
        self.port = port
        self.msgCount = 0
        print("[+] New server socket thread started for " + ip + ":" + str(port))

    def run(self):
        while True:
            data = self.conn.recv(2048)
            now = datetime.now()
            current_time = now.strftime("%H:%M:%S")
            print("Server received data:" + str(self.msgCount) + ":" + str(data) + ":" + current_time)
            print()
            MESSAGE = "Server received your message number " + str(self.msgCount)
            MESSAGE_BYTES = bytes(MESSAGE, 'utf-8')
            self.conn.send(MESSAGE_BYTES)
            if data == b'exit':
                break
            self.msgCount += 1
        try:
            self.conn.close()
        except Exception:
            pass

TCP_IP = '0.0.0.0'
TCP_PORT = 2004

tcpServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcpServer.bind((TCP_IP, TCP_PORT))
threads = []

while True:
    tcpServer.listen(4)
    print("Server : Waiting for connections from TCP clients...")
    (conn, (ip, port)) = tcpServer.accept()
    newthread = ClientThread(conn, ip, port)
    newthread.start()
    threads.append(newthread)
