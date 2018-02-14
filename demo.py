from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import os
import crypto_functions

#simple implementation of a "blockchain" as a list of Block objects
blocks = []

#User class. Stores personal information about the user
class User(object):
	def __init__(self,name,postal_code,id_number,dob):
		self.name = name
		self.postal_code = postal_code
		self.id_number = id_number
		self.dob = dob

	#set the user's token after it has been created by KYC service
	def setToken(self, token):
		self.token = token

#A class representing a block in the blockchain. Stores the user's encrypted information
class Block(object):
	id_list = []
	def __init__(self,info):
		self.info = info

		#generate block id
		#in this simple implementation, it is simply the last unoccupied slot in the list of blocks,
		#which was defined at the start of this file
		self.id = len(blocks)

		#add block to the list of blocks
		blocks.append(self)

#Class representing a user's token. Stores the RSA private key, AES key, and user's block id.
class Token(object):
	def __init__(self, RSA_pvt_key, AES_key, block_id):
		self.RSA_pvt_key = RSA_pvt_key
		self.AES_key = AES_key
		self.block_id = block_id

#function which allows a user to register with the KYC service
def register_kyc(user):
	#extract user info, and generate public-private key
	user_info = user.__dict__
	AES_key = Random.new().read(32)
	RSA_pvt_key = RSA.generate(2048)
	RSA_pub_key = RSA_pvt_key.publickey()

	#create Merkle tree hash from user information, and add it to the dictionary
	hashed_info = [crypto_functions.hash256(item) for item in user_info.values()]
	merkle = crypto_functions.merkle(hashed_info)
	user_info["merkle"] = merkle

	#write key to the file then read the same file to obtain the key in plaintext
	f = open("publicKey.pem", "a+b")
	f.write(RSA_pub_key.exportKey('PEM'))
	f.seek(0)
	RSA_pub_key_str = f.read()
	f.close()

	#delete file after this to prevent key from being stored as a file
	os.remove("publicKey.pem")
	user_info["public_key"] = RSA_pub_key_str

	#encrypt the information (except RSA private key) and store it on the block
	encrypted_user_info = {}
	for key in user_info:
		encrypted_user_info[crypto_functions.aes_encrypt(key, AES_key)] = crypto_functions.aes_encrypt(user_info[key], AES_key)
	
	block = Block(encrypted_user_info)

	#store private key, AES key, and user's block id in the token
	#first get private key as plaintext
	f = open("privateKey.pem", "a+b")
	f.write(RSA_pvt_key.exportKey('PEM'))
	f.seek(0)
	RSA_pvt_key_str = f.read()
	f.close()

	#delete file after this to prevent key from being stored as a file
	os.remove("privateKey.pem")

	#create the token object, and assign it to the user who is registering
	token = Token(RSA_pvt_key_str,AES_key,block.id)
	user.setToken(token)


print("What would you like to do?")
print("1 Register for KYC service")
choice = input()
if (choice == "1"):
	name = input("Sure! Please enter your full name: ")
	postal_code = input("Please enter your postal code: ")
	id_number = input("Please enter your id number: ")
	dob = input("Please enter your date of birth in DD/MM/YYYY format: ")
	user = User(name = name, postal_code = postal_code, id_number = id_number, dob = dob)
	print("registration complete")
else:
	print("invalid choice, please try again")

register_kyc(user)





