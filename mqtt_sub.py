#!/usr/bin/env python3

import argparse
import paho.mqtt.client as mqtt 
import requests
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.pairinggroup import PairingGroup,pair
from charm.core.engine.util import bytesToObject
from base64 import b64decode
from Crypto.Cipher import AES
from datetime import datetime

class Dec():
    def __init__(self, groupObj):
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj

    def cpabe_decrypt(self, pk, sk, ct):
        policy = self.util.createPolicy(ct['policy'])
        pruned_list = self.util.prune(policy, sk['S'])
        if pruned_list == False:
            return False
        z = self.util.getCoefficients(policy)
        A = 1
        for i in pruned_list:
            j = i.getAttributeAndIndex(); k = i.getAttribute()
            A *= ( pair(ct['Cy'][j], sk['Dj'][k]) / pair(sk['Djp'][k], ct['Cyp'][j]) ) ** z[j]
        return ct['C_tilde'] / (pair(ct['C'], sk['D']) / A)

    def decrypt(self, pk, sk, payload):
        ct = bytesToObject(payload, self.group)
        encrypted_aes_key = ct['encrypted_aes_key']
        aes_key = self.cpabe_decrypt(pk, sk, encrypted_aes_key)
        if aes_key:
            aes_key_bytes = self.group.serialize(aes_key)

            encrypted_data = ct['encrypted_data']
            encrypted_data_k = ['nonce', 'ciphertext', 'tag']
            encrypted_data = {k:b64decode(encrypted_data[k]) for k in encrypted_data_k}
            cipher = AES.new(aes_key_bytes[:16], AES.MODE_EAX, nonce=encrypted_data['nonce'])
            msg = cipher.decrypt_and_verify(encrypted_data['ciphertext'], encrypted_data['tag'])
            return msg.decode()
        else:
            return False

def on_connect(client, userdata, flags, rc):
    client.subscribe(userdata['topic'])

def on_subscribe(client, userdata, mid, granted_qos):
    print('--------------------------------------------------------------------------------')
    print(datetime.now().strftime("%d/%m/%Y %H:%M:%S") + ' Suscrito: ' + userdata['topic'])
    print('--------------------------------------------------------------------------------')

def on_message(client, userdata, message):
    msg = userdata['dec'].decrypt(userdata['pk'], userdata['sk'], message.payload)
    if msg:
        print('--------------------------------------------------------------------------------')
        print(datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
        print('msg: ' + msg)
        print('topic: ' + str(message.topic))
        print('--------------------------------------------------------------------------------')

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--host', '-h', required=True)
    parser.add_argument('--topic', '-t', required=True)
    parser.add_argument('--attributes', '-at', required=True)
    parser.add_argument('--client_id', '-i')
    args = parser.parse_args()

    mqttBroker = args.host
    topic = args.topic
    attributes = args.attributes

    PORT = '8000'
    group = PairingGroup('SS512')
    util = SecretUtil(group, verbose=False)

    pk = bytesToObject(requests.get('http://' + mqttBroker
        + ':' + PORT + '/pk').content, group)

    dec = Dec(group)

    parameters = ''
    attributes_list = attributes.split()
    for i in range(len(attributes_list)):
        parameters += 'a' + str(i) + '=' + attributes_list[i].upper()
        if i < len(attributes_list) - 1:
            parameters += '&'

    sk = bytesToObject(requests.get('http://' + mqttBroker
        + ':' + PORT + '/keygen?' + parameters).content, group)

    client = mqtt.Client(args.client_id, userdata={'dec': dec, 'pk': pk, 'sk': sk, 'topic': topic})
    client.connect(mqttBroker) 
    client.on_connect=on_connect
    client.on_subscribe=on_subscribe
    client.on_message=on_message 
    client.loop_forever()

if __name__ == '__main__':
    main()
