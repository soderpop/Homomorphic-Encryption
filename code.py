import random
import sys
import os
import math
import time
import hashlib
import base64
import binascii
import string
import fractions
import itertools
import sympy
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import matplotlib.mlab as mlab
import scipy.stats as stats
import scipy.special as special
import scipy.optimize as optimize
#import scipy.weave as weave
import scipy.fftpack as fftpack
import scipy.integrate as integrate
import scipy.ndimage as ndimage
import scipy.cluster as cluster
import scipy.spatial as spatial
import scipy.cluster.hierarchy as hierarchy
import scipy.sparse as sparse
import scipy.linalg as linalg
import scipy.fftpack as fftpack
import scipy.signal as signal
import scipy.interpolate as interpolate
import scipy.ndimage.filters as filters
import scipy.ndimage.morphology as morphology
import scipy.ndimage.measurements as measurements


p = sympy.prime(random.randint(1, 100)) #this is the first prime number
q = sympy.prime(random.randint(1, 100)) #this is the second prime number
e = sympy.prime(random.randint(1, 100)) #this is the public key
n = (p*q) #this is the modulus


def HomomorphicEncryption(self, p, q, e, n): #this code is used to create the public and private keys
        self.p = p
        self.q = q
        self.e = e
        self.n = n
        self.phi = (p-1)*(q-1)
        self.d = self.find_d()
        self.ciphertext = 0
        self.plaintext = 0
        self.message = 0
        self.message_hash = 0
        self.message_hash_hex = 0
        self.message_hash_base64 = 0
        self.message_hash_base64_url = 0
        self.message_hash_base64_url_hex = 0
        self.message_hash_base64_url_hex_sha256 = 0
        
def find_d(self): #this code is used to find the private key
        d = sympy.mod_inverse(self.e, self.phi)
        return d

def encrypt(self, message): #this code is used to encrypt the message
        self.message = message
        self.message_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
        self.message_hash_hex = binascii.hexlify(message.encode('utf-8')).decode('utf-8')
        self.message_hash_base64 = base64.b64encode(message.encode('utf-8')).decode('utf-8')
        self.message_hash_base64_url = base64.urlsafe_b64encode(message.encode('utf-8')).decode('utf-8')
        self.message_hash_base64_url_hex = binascii.hexlify(base64.urlsafe_b64encode(message.encode('utf-8'))).decode('utf-8')
        self.message_hash_base64_url_hex_sha256 = hashlib.sha256(base64.urlsafe_b64encode(message.encode('utf-8'))).hexdigest()
        self.ciphertext = pow(int(self.message_hash_base64_url_hex, 16), self.e, self.n)
        return self.ciphertext

def decrypt(self, ciphertext): #this code is used to decrypt the message using base64
        self.ciphertext = ciphertext
        self.plaintext = pow(self.ciphertext, self.d, self.n)
        return self.plaintext

def decrypt_hex(self, ciphertext): #this code is used to decrypt the message using hexadecimal
        self.ciphertext = ciphertext
        self.plaintext = pow(self.ciphertext, self.d, self.n)
        self.plaintext_hex = hex(self.plaintext)
        return self.plaintext_hex

def decrypt_base64(self, ciphertext): #this code is used to decrypt the message using base64 
        self.ciphertext = ciphertext
        self.plaintext = pow(self.ciphertext, self.d, self.n)
        self.plaintext_base64 = base64.b64encode(self.plaintext).decode('utf-8')
        return self.plaintext_base64

def decrypt_base64_url(self, ciphertext): #this code is used to decrypt the message using base64 url
        self.ciphertext = ciphertext
        self.plaintext = pow(self.ciphertext, self.d, self.n)
        self.plaintext_base64_url = base64.urlsafe_b64encode(self.plaintext).decode('utf-8')
        return self.plaintext_base64_url

def decrypt_base64_url_hex(self, ciphertext): #this code is used to decrypt the message using base64 url and hexadecimal
        self.ciphertext = ciphertext
        self.plaintext = pow(self.ciphertext, self.d, self.n)
        self.plaintext_base64_url_hex = binascii.hexlify(base64.urlsafe_b64encode(self.plaintext)).decode('utf-8')
        return self.plaintext_base64_url_hex

def decrypt_base64_url_hex_sha256(self, ciphertext): #this code is used to decrypt the message using
        self.ciphertext = ciphertext
        self.plaintext = pow(self.ciphertext, self.d, self.n)
        self.plaintext_base64_url_hex_sha256 = hashlib.sha256(base64.urlsafe_b64encode(self.plaintext)).hexdigest()
        return self.plaintext_base64_url_hex_sha256


def main():  #this code is used to run the program
    p = int(input("Enter p: "))
    q = int(input("Enter q: "))
    e = int(input("Enter e: "))
    n = p*q
    h = HomomorphicEncryption(p, q, e, n)
    message = input("Enter message: ")
    ciphertext = h.encrypt(message)
    print("Ciphertext: ", ciphertext)
    plaintext = h.decrypt(ciphertext)
    print("Plaintext: ", plaintext)
    plaintext_hex = h.decrypt_hex(ciphertext)
    print("Plaintext hex: ", plaintext_hex)
    plaintext_base64 = h.decrypt_base64(ciphertext)
    print("Plaintext base64: ", plaintext_base64)
    plaintext_base64_url = h.decrypt_base64_url(ciphertext)
    print("Plaintext base64 url: ", plaintext_base64_url)
    plaintext_base64_url_hex = h.decrypt_base64_url_hex(ciphertext)
    print("Plaintext base64 url hex: ", plaintext_base64_url_hex)
    plaintext_base64_url_hex_sha256 = h.decrypt_base64_url_hex_sha256(ciphertext)
    print("Plaintext base64 url hex sha256: ", plaintext_base64_url_hex_sha256)


if __name__ == "__main__": #this code is used to run the program
    main()
    #print(message)
    #print(p)
    #print(q)
    #print(e)
    #print(n)
    #print(phi)
    #print(d)
    #print(ciphertext)
    #print(plaintext)
    #print(message_hash)
    #print(message_hash_hex)
    #print(message_hash_base64)
    #print(message_hash_base64_url)
    #print(message_hash_base64_url_hex)
    #print(message_hash_base64_url_hex_sha256)
