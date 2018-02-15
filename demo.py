from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import os
import crypto_functions
import ast
import copy
import getpass

#simple implementation of a "blockchain" as a list of Block objects
blocks = []

#dictionary, with id numbers as keys, to store user objects for demo purposes
users = {}

#dictionary, with organization names as keys, to store organization objects for demo purposes
orgs = {}

#User class. Stores personal information about the user
class User(object):
	def __init__(self,name,postal_code,id_number,dob):
		self.name = name
		self.postal_code = postal_code
		self.id_number = id_number
		self.dob = dob
		users[self.id_number] = self

	#set the user's token after it has been created by KYC service
	def setToken(self, token):
		self.token = token

	#receive a public key from an organization that the user is signing up for
	def receiveKey(self, key):
		self.registration_key = key

	#transmits data to the organization. 
	#typically, this would either be the AES key and block number to permit the org to obtain the user's info,
	#or it would be the merkel root used for authentication
	def sendToOrg(self,message, org):
		org.receiveMessage(message)

	#re-encrypts the data on the block with a new AES key
	def reencrypt(self):
		#first get the old data from the block using the token
		block_id = self.token.block_id
		encrypted_info = blocks[int(block_id)].info
		decrypted_info = {}
		aes_key = self.token.AES_key
		for key in encrypted_info:
			decrypted_info[crypto_functions.aes_decrypt(key, aes_key)] = crypto_functions.aes_decrypt(encrypted_info[key], aes_key)

		#then generate the new key, re-encrypt the data and put it on the block
		new_key = Random.new().read(32)
		block = blocks[int(block_id)]
		user_info = block.info
		encrypted_user_info = {}
		for key in user_info:
			encrypted_user_info[crypto_functions.aes_encrypt(key, new_key)] = crypto_functions.aes_encrypt(user_info[key], new_key)
		block.info = encrypted_user_info
	
					
		
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

#Class representing a user's token. Stores the RSA private key, AES key, user's block id, and required info to compute merkle tree root hash
class Token(object):
	def __init__(self, RSA_pvt_key, AES_key, block_id,merkle_raw):
		self.RSA_pvt_key = RSA_pvt_key
		self.AES_key = AES_key
		self.block_id = block_id
		self.merkle_raw = merkle_raw

#a class used to store a user's information into an organization's database
class UserInfo(object):
	def __init__(self,name,postal_code,id_number,dob,username,password_hash,merkle,public_key):
		self.name = name
		self.postal_code = postal_code
		self.id_number = id_number
		self.dob = dob
		self.username = username
		self.password_hash = password_hash
		self.merkle = merkle
		self.public_key = public_key


class Organization(object):
	database = {}
	def __init__(self, name):
		self.name = name

	#generates a pair of public and private RSA keys
	def generateKey(self):
		self.RSA_pvt_key = RSA.generate(2048)
		self.RSA_pub_key = self.RSA_pvt_key.publickey()

	#sends the public key to the user, which allows him to encrypt his AES key before sending it over
	def sendPublicKey(self,user):
		user.receiveKey(self.RSA_pub_key)

	def receiveMessage(self,message):
		self.recievedMessage = message

	#inform user that registration is successful
	#upon successful registration, user scans token to re-encrypt their data on the block
	def sendUserRegSuccess(self,user):
		user.reencrypt()

	#handle any incoming requests from users
	#two possible requests: register and login
	def handleRequest(self, request):
		#register
		if request['request'] == 'register':
			aes_key = request["aes_key"]
			block_id = request['block_id']
			username = request["username"]
			password_hash = request["password_hash"]
			block = blocks[int(block_id)]
			encrypted_info = block.info

			#decrypt info on the block using the user's AES key
			decrypted_info = {}
			for key in encrypted_info:
				decrypted_info[crypto_functions.aes_decrypt(key, aes_key)] = crypto_functions.aes_decrypt(encrypted_info[key], aes_key)

			#add the decrypted info into the org's database
			self.database[username] = UserInfo(decrypted_info["name"],decrypted_info["postal_code"], decrypted_info["id_number"], decrypted_info["dob"],username,password_hash,decrypted_info["merkle"], decrypted_info["public_key"])

			#inform user that registration is successful
			self.sendUserRegSuccess(users[decrypted_info["id_number"]])

		#login
		elif request['request'] == 'login':
			username = request["username"]
			password_hash = request["password_hash"]
			signature = request['signature']
			if (username in self.database):
				userinfo = self.database[username]

			else:
				print("Login failed. Invalid username")


			#check if password is correct
			if password_hash != userinfo.password_hash:
				print("Login failed. Wrong password")
				return

			#verify identity using digital signature
			try:
				hash_object = SHA256.new(data = bytes(userinfo.merkle, encoding = "utf-8"))
				public_key = RSA.import_key(userinfo.public_key)
				pkcs1_15.new(public_key).verify(hash_object, signature)
				print("Login successful")

			except ValueError:
				print("Login failed, could not verify identity")
				self.handleRequest(request)

#function which allows a user to register with the KYC service
def register_kyc(user):
	#extract user info, and generate public-private key
	user_info = user.__dict__
	AES_key = Random.new().read(32)
	RSA_pvt_key = RSA.generate(2048)
	RSA_pub_key = RSA_pvt_key.publickey()

	#create Merkle tree hash from user information, and add it to the dictionary
	merkle_raw = user_info.copy().values() #make a copy of the information used to create the merkle tree
	hashed_info = [crypto_functions.hash256(item) for item in merkle_raw]
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
	token = Token(RSA_pvt_key_str,AES_key,block.id,merkle_raw)
	user.setToken(token)

#function which allows a user to register with a organization, provided that he has already registered with KYC service
def register_org(user,org):
	#organization first generates a public-private key pair, and sends the public key to the user
	org.generateKey()
	org.sendPublicKey(user)
	#user inputs the username and password that he wants

	username = input("Registration: please enter username: ")
	password = getpass.getpass("Please enter password: ")
	password_hash = crypto_functions.hash256(password)

	#password is stored as hash for security reasons
	#user scans his token, and the block id and AES key is encrypted using the public key and sent back to the organization
	#simulation of virtual token, type in ID number to scan token
	token = users[input("Please scan your token: ")].token
	message = "{'request': 'register', 'block_id': '%s', 'username': '%s', 'password_hash': '%s', 'aes_key': %s}" %(token.block_id,username, password_hash, token.AES_key)
	user.sendToOrg(crypto_functions.rsa_encrypt(message,user.registration_key),org)

	#org decrypts the message with their private key and handles the message
	#in this case, the user's request is for registration, and that will be done under the handleRequest method of the org
	decrypted = crypto_functions.rsa_decrypt(org.recievedMessage,org.RSA_pvt_key)
	user_request = ast.literal_eval(decrypted) #convert message to dict
	org.handleRequest(user_request)

#function for users to log in
def login_org(org):
	username = input("Login: please enter username: ")
	password = getpass.getpass("Please enter password: ")
	password_hash = crypto_functions.hash256(password)
	#simulation of virtual token, type in ID number to scan token
	try:
		token = users[input("Please scan your token: ")].token
	except:
		print("login failed, invalid token")

	#compute merkle tree root from information stored in token
	hashed_info = [crypto_functions.hash256(item) for item in token.merkle_raw]
	merkle = crypto_functions.merkle(hashed_info)
	#create digital signature by encrypting the merkle root using RSA
	hash_object = SHA256.new(data = bytes(merkle, encoding = "utf-8"))
	privateKey = RSA.import_key(token.RSA_pvt_key)
	signature = pkcs1_15.new(privateKey).sign(hash_object)

	#send login request to organization
	request = {'request': 'login', 'username': username, 'password_hash': password_hash, 'signature': signature}
	org.handleRequest(request)
	
while (True):
	print("What would you like to do?")
	print("1 Register for KYC service")
	print("2 Register with an organization")
	print("3 Login to an organization")
	choice = input()
	if (choice == "1"):
		name = input("Please enter your full name: ")
		postal_code = input("Please enter your postal code: ")
		id_number = input("Please enter your id number: ")
		dob = input("Please enter your date of birth in DD/MM/YYYY format: ")
		user = User(name = name, postal_code = postal_code, id_number = id_number, dob = dob)
		register_kyc(user)
		print("registration complete")

	elif choice == "2":
		user_id = input("Enter your id number: ")
		user = users[user_id]
		org_name = input("Enter the name of the organization you are registering for: ")
		if org_name not in orgs:
			org = Organization(org_name)
			orgs[org_name] = org
		else:
			org = orgs[org_name]
		register_org(user, org)

	elif choice == "3":
		org_name = input("Enter the name of the organization you are logging in to: ")
		if org_name not in orgs:
			org = Organization(org_name)
			orgs[org_name] = org
		else:
			org = orgs[org_name]
		login_org(org)
	else:
		print("invalid choice, please try again")





