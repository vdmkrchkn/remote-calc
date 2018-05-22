# test

import threading, socket, random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

def reqNum():
    return 'NMR '+str(random.randrange(100))

def reqSum():
    return 'SUM'

def EncryptAES(key,msg):
    SYM = b'!'
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key,AES.MODE_CBC,iv)    
    # функция дополнения
    pad = lambda s: s + SYM*(AES.block_size - len(s) % AES.block_size)        
    ciphertext = iv
    ciphertext += cipher.encrypt(pad(msg))
    return ciphertext    

def DecryptAES(key,msg):
    SYM = b'!'
    cipher = AES.new(key,AES.MODE_CBC,msg[:AES.block_size])
    plaintext = cipher.decrypt(msg[AES.block_size:])
    return plaintext.rstrip(SYM)

def client_work(name,lock):
    HOST, PORT = "localhost", 9999
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    s.sendall('HLO {}'.format(name).encode('utf-8'))
    key = RSA.generate(1024)
    s.sendall(key.publickey().exportKey())
    response = s.recv(1024)
    sessionKey = key.decrypt(response)

    for i in range(10):
        action = random.randint(0,1)
        request = reqNum() if action else reqSum()
        lock.acquire()
        s.sendall(EncryptAES(sessionKey,request.encode('utf-8')))
        lock.release()
        print('<{0}>:{1}'.format(name,request))
        if not action:
            s.recv(1024)
    s.sendall(EncryptAES(sessionKey,'BYE'.encode('utf-8')))
    s.close()

threads = []
client_names = ('Alice','Bob','Napoleon','Snowball','Squealer','Minimus','Pinkeye','Boxer','Clover','Mollie')
lock = threading.Lock()
for i in range(10):
    threads.append(threading.Thread(target=client_work,args=(client_names[i],lock)))    
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
    
