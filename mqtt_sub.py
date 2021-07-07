#!/usr/bin/env python3

import argparse
import paho.mqtt.client as mqtt 
import requests
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.pairinggroup import PairingGroup,pair
from charm.core.engine.util import bytesToObject
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--host', '-h', required=True)
parser.add_argument('--topic', '-t', required=True)
parser.add_argument('--attributes', '-at', required=True)
parser.add_argument('--client_id', '-i')
args = parser.parse_args()

mqttBroker = args.host
topic = args.topic
attributes = args.attributes
client = mqtt.Client(args.client_id)

PORT = '8000'
group = PairingGroup('SS512')
util = SecretUtil(group, verbose=False)

pk = bytesToObject(requests.get('http://'
    + mqttBroker
    + ':'
    + PORT
    + '/pk').content, group)

parameters = ''
attributes_list = attributes.split()
for i in range(len(attributes_list)):
    parameters += 'a' + str(i) + '=' + attributes_list[i].upper()
    if i < len(attributes_list) - 1:
        parameters += '&'

sk = bytesToObject(requests.get('http://'
    + mqttBroker
    + ':'
    + PORT
    + '/keygen?'
    + parameters).content, group)

def cpabe_decrypt(pk, sk, ct):
    policy = util.createPolicy(ct['policy'])
    pruned_list = util.prune(policy, sk['S'])
    if pruned_list == False:
        return False
    z = util.getCoefficients(policy)
    A = 1
    for i in pruned_list:
        j = i.getAttributeAndIndex(); k = i.getAttribute()
        A *= ( pair(ct['Cy'][j], sk['Dj'][k]) / pair(sk['Djp'][k], ct['Cyp'][j]) ) ** z[j]
    return ct['C_tilde'] / (pair(ct['C'], sk['D']) / A)

def decrypt(payload):
    ct_dict = bytesToObject(payload, group)
    encrypted_aes_key_dict = ct_dict['encrypted_aes_key_dict']
    aes_key = cpabe_decrypt(pk, sk, encrypted_aes_key_dict)
    if aes_key:
        aes_key_bytes = group.serialize(aes_key)

        aes_encryption_dict = ct_dict['aes_encryption_dict']
        iv = b64decode(aes_encryption_dict['iv'])
        encrypted_data = b64decode(aes_encryption_dict['encrypted_data'])
        cipher = AES.new(aes_key_bytes[:16], AES.MODE_CBC, iv)
        msg = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return msg.decode()
    else:
        return False

def on_connect(client, userdata, flags, rc):
    client.subscribe(args.topic)

def on_subscribe(client, userdata, mid, granted_qos):
    print('--------------------------------------------------------------------------------')
    print(datetime.now().strftime("%d/%m/%Y %H:%M:%S") + ' Suscrito: ' + topic)
    print('--------------------------------------------------------------------------------')

def on_message(client, userdata, message):
    msg = decrypt(message.payload)
    if msg:
        print('--------------------------------------------------------------------------------')
        print(datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
        print('msg: ' + msg)
        print('topic: ' + str(message.topic))
        print('--------------------------------------------------------------------------------')

def main():
    client.connect(mqttBroker) 
    client.on_connect=on_connect
    client.on_subscribe=on_subscribe
    client.on_message=on_message 
    client.loop_forever()

if __name__ == '__main__':
    main()
