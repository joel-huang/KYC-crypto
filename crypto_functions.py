from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64

#function which encrypts data using AES
def aes_encrypt(data,key):
	#process data to become suitable for encryption by padding and by converting to bytes if needed
	if type(data) != bytes:
		data = bytes(data, encoding = "utf8")

	#pad until the data length is a multiple of 16; needed for encryption
	length = 16 - (len(data) % 16)
	data += bytes([length])*length
		
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, iv)

	return (base64.b64encode(iv + cipher.encrypt(data)).decode())


#computes a SHA256 hash of the data
def hash256(data):
	data = bytes(data, encoding = "utf8")
	hash_object = SHA256.new(data=data)
	return hash_object.hexdigest()

#function that returns the root hash of the merkle tree from a list of data
#it assumes that everything in the data has already been hashed
def merkle(data):
	#base case, only one data point, return hash of that one data point
	if len(data) == 1:
		return data[0]

	#another base case, compute hash of the concatenation of the 2 leaves
	if len(data) == 2:
		return hash256(data[0] + data[1])

	#if odd number, ignore last data point  
	if (len(data)%2 != 0):
		data = data[:-1]

	#recursively traverse the merkle tree from bottom to top to get the root hash
	temp = []
	for i in range(0,len(data),2):
		temp.append(merkle(data[i:i+2]))

	return merkle(temp)




	