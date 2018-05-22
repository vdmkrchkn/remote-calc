# Server

import socket,threading,socketserver,os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        recv_message = str(self.request.recv(1024),'utf-8')        
        self.login = recv_message.split(' ')[1]
        print('<{0}>:{1}'.format(self.login,recv_message))

        self.pubkey = self.request.recv(1024)        
        self.sessionKey = os.urandom(16)#генерация сеансового ключа AES
        response = self.encryptByPublic()        
        self.request.sendall(response)
        
        self.sum = 0
        while True:        
            recv_message = self.request.recv(16)
            text = str(self.DecryptAES(recv_message),'utf-8')
            print('<{0}>:{1}'.format(self.login,text))
            ss = text.split(' ')
            command = ss[0] 
            if command == 'NMR':
                self.sum += int(ss[1])
                continue
            elif command == 'SUM':                
                response = self.EncryptAES(bytes(str(self.sum),'utf-8'))
                self.sum = 0
                self.request.sendall(response)
            else:
                break
            
            
    def encryptByPublic(self):                   
        key = RSA.importKey(self.pubkey)                
        ciphertext, *k = key.encrypt(self.sessionKey, 0)            
        return ciphertext  

    def EncryptAES(self,msg):
        SYM = b'!'
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.sessionKey,AES.MODE_CBC,iv)    
        # функция дополнения
        pad = lambda s: s + SYM*(AES.block_size - len(s) % AES.block_size)        
        ciphertext = iv
        ciphertext += cipher.encrypt(pad(msg))
        return ciphertext    

    def DecryptAES(self,msg):
        SYM = b'!'
        cipher = AES.new(self.sessionKey,AES.MODE_CBC,msg[:AES.block_size])
        plaintext = cipher.decrypt(msg[AES.block_size:])
        return plaintext.rstrip(SYM)

            
class ThreadedTCPServer(socketserver.ThreadingMixIn,socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    server = ThreadedTCPServer((HOST, PORT),ThreadedTCPRequestHandler)
    server.allow_reuse_address=True
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    c = input('')
    if c.upper() == 'EXIT':
        server.server_close()
