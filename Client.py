# Client

import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

SYM = b'!'

def EncryptAES(key,msg):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key,AES.MODE_CBC,iv)
    # функция дополнения
    pad = lambda s: s + SYM*(AES.block_size - len(s) % AES.block_size)
    ciphertext = iv
    ciphertext += cipher.encrypt(pad(msg))
    return ciphertext

def DecryptAES(key,msg):
    cipher = AES.new(key,AES.MODE_CBC,msg[:AES.block_size])
    plaintext = cipher.decrypt(msg[AES.block_size:])
    return plaintext.rstrip(SYM)

def instructions():
    """Вывод инструкций"""
    print(
        """
        HLO <логин> - соединение с сервером, передача открытого ключа
        NMR <число> - отправка серверу ЦЕЛОГО числа
        SUM         - получить сумму чисел со времени последнего
        запроса SUM
        BYE         - закрытие соединения
        HLP         - вызов справки
        """
        )

print(
    """
    Приложение, позволяющее суммировать последовательности
    целых чисел и обеспечивающее защищенную передачу данных.
    Пользователю доступны следующие команды:
    """
    )
instructions()

# подключение к серверу
HOST, PORT = "localhost", 9999
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
# ожидание ввода команды HLO
command = None
while command != 'HLO':
    c = input('')
    command = c[:3]
    s.sendall(c.encode('utf-8')) if command == 'HLO' else print('expected HLO')

# ожидание ввода команды PBK
while command != 'PBK':
    command = input('')
    if command != 'PBK':
        print('expected PBK')
# загрузка открытого ключа и дальнейшая отправка на сервер
try:
    key = RSA.importKey(open('pubkey.pem','rb').read())
    s.sendall(key.exportKey())
    response = s.recv(1024)
except IOError:
    print('Ошибка чтения файла с ключами')
#print(response)

# дешифрование закрытым ключом сеансового ключа
try:
    key = RSA.importKey(open('mykey.pem','rb').read())
    sessionKey = key.decrypt(response)
except IOError:
    print('Ошибка чтения файла с ключами')

# работа с сервером
COMMANDS = ('NMR','SUM','BYE','HLP')
while True:
    command = input('')
    if command == 'HLP':# вызов справки
        instructions()
        continue
    if command[:3] not in COMMANDS: # неверная команда
        print('Неверная команда!Вызовите HLP для получения справки')
        continue
    s.sendall(EncryptAES(sessionKey,command.encode('utf-8')))
    if command == 'BYE':
        break
    if command == 'SUM':
        response = s.recv(1024)
        print(DecryptAES(sessionKey,response).decode('utf-8'))

s.close()
