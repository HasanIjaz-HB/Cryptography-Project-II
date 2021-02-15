import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Hash import HMAC, SHA256
import random
import re
import json
API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID =  24775


#create a long term key
def key_generation(n,P):
     sA = random.randrange(0,n-1)
     QA = sA*P
     return sA,QA
 
def signature_generation(n,m,P,sA):
    k = random.randrange(1, n-2)
    R = k*P
    r = R.x % n
    temp = m + r.to_bytes((r.bit_length() + 7) // 8,byteorder= 'big')
    h = SHA3_256.new(temp)
    h = int.from_bytes(h.digest(), byteorder='big') % n
    s = (sA*h + k) % n
    return(h,s)

def signature_verification(message,K_MAC):
    message = message.to_bytes((message.bit_length()+7)//8, byteorder='big')
    txt = message[8:-32]
    result = HMAC.new(K_MAC, digestmod=SHA256)
    cmac = message[-32:]
    txtup = result.update(txt)
    txtup = txtup.digest()
    #print(K_MAC)
    #print(txtup)
    #result.hexverify(K_MAC)
    #print("Message verified")
    
curve = Curve.get_curve('secp256k1')
n = curve.order
P = curve.generator

#sA_l,QA_l=key_generation(n, P);
sA_l = 47739507727097583103574014533029612368096643715089728534014772436197620809295 #long term key
QA_l = sA_l*P
lkey=QA_l
lpkey=sA_l
print('sA_l:',sA_l)
print('QA_l:',QA_l)
m = str(stuID)
m = str.encode(m)
h,s = signature_generation(n, m, P, sA_l)

#server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9 , 0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, curve)

####Register Long Term Key
mes = {'ID':stuID, 'H': h, 'S': s, 'LKEY.X': lkey.x, 'LKEY.Y': lkey.y}
response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json = mes)
print(response.json())
print("code:")  
code = input()
#code is 789746
mes = {'ID':stuID, 'CODE': code}
response = requests.put('{}/{}'.format(API_URL, "RegLong"), json = mes)
print(response.json())


#send ephemeral key
arraysA = []
arrayQA = []
h_temp=[]
s_temp= []

for i in range(0,10):
    sA,QA  = key_generation(n, P) 
    mes = (str(QA.x)+str(QA.y)).encode()
    arraysA.append(sA)
    arrayQA.append(QA)
    hx, sx = signature_generation(n,mes,P,sA_l)
    #send ephemeral key
    mes = {'ID': stuID, 'KEYID': i , 'QAI.X':QA.x, 'QAI.Y': QA.y, 'Si': sx, 'Hi': hx}
    response = requests.put('{}/{}'.format(API_URL, "SendKey"), json = mes)
    print('Response_1: ',response.json())

#Receiving Messages
for i in range(10):
    mes = {'ID_A': stuID, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)
    print(response.json())
    res = response.json()
    mes = res['MSG']
    QBj = Point(res['QBJ.X'] , res['QBJ.Y'], curve)
    
    T = arraysA[i] * QBj
    strg = "NoNeedToRunAndHide"
    U = str(T.x) + str(T.y) + strg
    U = str.encode(U)
    K_ENC = SHA3_256.new(U)
    K_ENC = K_ENC.digest()
    K_MAC = SHA3_256.new(K_ENC)
    K_MAC = K_MAC.digest()
    
    signature_verification(mes,K_MAC)
    #decrypt messages
    txt= mes.to_bytes((mes.bit_length()+7)//8, byteorder='big')
    cipher = AES.new(K_ENC, AES.MODE_CTR,  nonce=txt[:8])
    dtext = cipher.decrypt(txt[8:-32]).decode()
    print("dtext: ", dtext) 
    #send decrypted messages to server
    mes = {'ID_A': stuID, 'DECMSG': str(dtext)}
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
    print(response.json())




###delete ephemeral keys
mes = {'ID': stuID, 'S': s, 'H': h}
response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json = mes)



###########DELETE LONG TERM KEY
# If you lost your long term key, you can reset it yourself with below code.

# First you need to send a request to delete it. 
# =============================================================================
# mes = {'ID': stuID}
# response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json = mes)
# #Then server will send a verification code to your email. 
# # Send this code to server using below code
# code = 392263
# mes = {'ID': stuID, 'CODE': code}
# response = requests.get('{}/{}'.format(API_URL, "RstLong"), json = mes)
# print(response.json())
# 
# =============================================================================
#Now your long term key is deleted. You can register again. 

