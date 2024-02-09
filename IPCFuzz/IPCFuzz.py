
import os
import sys

from ctypes import *
import glob
import shutil

from util import *
import secrets

# Script for fuzzing IPC endpoints on QNX
# Uses /dev/name/local to get endpoints
# Monitors /var/log/ for crashes

# <alex.plaskett@mwrinfosecurity.com>

class ClientMsg(Structure):
	_fields_ = [("msg_no", c_short), ("buffer", c_char * 1024)]

class _name_attach(Structure):
	_fields_ = [
	("dpp", c_ulong),
	("chid", c_ulong),
    ("mntid", c_ulong),
    ("zero", c_ulong)
    ]

class IPCFuzz:
	def __init__(self):
		"""This function initializes the object with the necessary attributes and variables. It sets the libc variable to the CDLL object for the "libc.so" library. It also initializes the coids list and calls the init_endpoints() function. It sets the nto_side_channel variable to the value 1073741824 and the crash_dir variable to the "./crashes/" directory. It also initializes the util variable to the Util() object and sets the is_simulator variable to False. Lastly, it calls the clean_corefile() function.
		Parameters:
		- None
		Returns:
		- None
		Processing Logic:
		- Initializes necessary attributes and variables.
		- Sets libc, coids, nto_side_channel, crash_dir, util, and is_simulator variables.
		- Calls init_endpoints() and clean_corefile() functions."""
		
		self.libc = CDLL("libc.so")
		self.coids = []
		self.init_endpoints()
		self.nto_side_channel= 1073741824 # nto_side_channel (not sure this is correct)
		self.crash_dir = "./crashes/"
		self.util = Util()
		self.is_simulator = False
		self.clean_corefile()

	""" Remove any core files from the directory before fuzzing """
	def clean_corefile(self):
		""""Creates a directory for crashes and removes all core files from the /var/log directory.
		Parameters:
		- self (object): The object that the function is being called on.
		Returns:
		- None: No return value.
		Processing Logic:
		- Creates a directory for crashes.
		- Removes all core files from the /var/log directory.
		- Uses the os.system() function to execute shell commands.""""
		
		os.system("mkdir crashes")
		os.system("rm -rf /var/log/*.core")

	""" The IPC endpoints we don't want to fuzz """ 
	def create_blacklist(self):
		"""Creates a blacklist of processes that cause blocking or are not relevant for the function's purpose.
		Parameters:
		- self (object): The object that the function is being called on.
		Returns:
		- blacklist (list): A list of processes to be blacklisted.
		Processing Logic:
		- Creates a list of processes.
		- Processes that cause blocking are included.
		- Processes that are not relevant are included.
		- Processes that are only applicable for simulator are included."""
		
		blacklist = ["battmgr_monitor",  		# Causes blocking 
					"battmgr", 
					"led_control", 				# Also blocks
					"VirtualEventServer",
					"svga_ch", 					# Simulator only
					"slogger2",
					# Device
					"io-asr-bb10", 			# blocks
					"dsi_server_primary", 	# blocks
					"phone-service" 		
					]

		return blacklist

	def init_endpoints(self):
		"""Function:
		Initializes the endpoints and creates a blacklist. Then loops through the endpoints and adds them to a list if they are not in the blacklist and the length of sys.argv is equal to 1. Prints the coids.
		Parameters:
		- self (object): The object instance.
		Returns:
		- None: This function does not return anything.
		Processing Logic:
		- Initializes endpoints and creates blacklist.
		- Loops through endpoints and adds to list.
		- Prints coids."""
		
		self.endpoints = os.listdir("/dev/name/local")
		bl = self.create_blacklist()

		for endpoint in self.endpoints:
			# These two cause the fuzzer to block
			#print(endpoint)
			if endpoint in bl and len(sys.argv) == 1:
				continue
			#if "battmgr_monitor" in endpoint or "led_control" in endpoint:
			#	continue
			coid = self.get_coid(endpoint)
			self.coids.append((coid,endpoint))

		print("coids are: ")
		for coid in self.coids:
			print(coid)

	def random_endpoint(self):
		""""Selects a random endpoint from a list of endpoints and returns it."
		Parameters:
		- self (object): Instance of the class.
		Returns:
		- endpoint (str): A randomly selected endpoint from the list of endpoints.
		Processing Logic:
		- Uses the secrets module to generate a random selection.
		- Prints the selected endpoint for confirmation.
		- Returns the selected endpoint."""
		
		endpoint = secrets.SystemRandom().choice(self.endpoints)
		print("endpoint selected = ", endpoint)
		return endpoint

	def random_coid(self):
		"""[0]
		Returns a randomly selected coid from a list of coids.
		Parameters:
		- self (object): The object containing the list of coids.
		Returns:
		- coid (str): The randomly selected coid.
		Processing Logic:
		- Uses the secrets module to generate a random choice.
		- Prints the selected coid and its corresponding endpoint.
		- Returns only the coid, not the endpoint.
		Example:
		If self.coids = [('ABC123', 'https://example.com'), ('DEF456', 'https://test.com')]
		Then random_coid(self) could return 'DEF456' and print:
		coid selected = DEF456
		endpoint = https://test.com"""
		
		coid = secrets.SystemRandom().choice(self.coids)
		print("coid selected = ", coid[0])
		print("endpoint = ", coid[1])
		return coid

	# Unicode str needs converted to byte string literal 
	#coid = libc.name_open(b"MercuryComponent",0)
	def get_coid(self,name):
		""""Returns the coid associated with the given name."
		Parameters:
		- name (str): The name to retrieve the coid for.
		Returns:
		- coid (int): The coid associated with the given name.
		Processing Logic:
		- Converts the name to bytes.
		- Opens the name using the libc library.
		- Prints the coid.
		- Returns the coid."""
		
		coid = self.libc.name_open(bytes(name, encoding='utf-8'),0)
		print("coid = ", coid)
		return coid

	# /proc/mount stuff
	def proc_mount_list(self):
		""""Processes and returns a list of mounted file systems from the /proc/mount directory."
		Parameters:
		- self (object): The object instance of the class.
		Returns:
		- list: A list of mounted file systems from the /proc/mount directory.
		Processing Logic:
		- Get list of files from /proc/mount directory.
		- Loop through each file.
		- Split file name by comma.
		- Ignore any errors."""
		
		arr = os.listdir("/proc/mount")
		for a in arr:
			try:
				# ND, ProcessId, ChannelId, Handle, FileType
				a.split(',')
			except:
				pass

	# Stock set of message lengths (should reverse out lengths expected)
	def message_size(self):
		"""Function to generate a random message size with a chance of a specific size.
		Parameters:
		- self (object): The object that the function is being called on.
		Returns:
		- size (int): The randomly generated message size.
		Processing Logic:
		- Generate a random number between 0 and 3000.
		- If the random number is divisible by 3, choose a size from the list [28, 0x1c, 512, 1024, 2046, 4096].
		- Otherwise, use the randomly generated number as the message size.
		- Print the message size.
		- Return the message size."""
		
		size = self.util.R(3000)

		if self.util.chance(3):
			arr = [28,0x1c,512,1024,2046,4096]
			size = self.util.choice(arr)

		print("msg size = ", size)
		return size

	def send_sync(self,coid,buf,size):
		"""Sends a synchronous message to a connection identified by coid, with the given buffer and size.
		Parameters:
		- coid (int): Connection identifier.
		- buf (bytes): Message buffer.
		- size (int): Size of the message buffer.
		Returns:
		- int: 0 if successful, -1 if failed.
		Processing Logic:
		- Prints the size of the message buffer.
		- Calls the MsgSend function from the libc library.
		- Prints an error message if MsgSend fails."""
		
		print(size)
		ret = self.libc.MsgSend(coid,buf,size,0,0)
		if ret == -1:
			print("MsgSend failed")

	# Even the Async call blocks
	def send_async(self,coid,buf,size):
		"""Sends a message asynchronously.
		Parameters:
		- coid (int): Connection ID of the recipient.
		- buf (bytes): Message to be sent.
		- size (int): Size of the message in bytes.
		Returns:
		- None: No return value.
		Processing Logic:
		- Uses libc library.
		- Calls MsgSendAsyncGbl function.
		- Prints error message if MsgSendAsyncGbl fails.
		- Exits the program if MsgSendAsyncGbl succeeds."""
		
		ret = self.libc.MsgSendAsyncGbl(coid,buf,size,0)
		if ret == -1:
			print("MsgSendAsyncGbl failed")
		else:
			sys.exit(0)

	""" Sometimes be a bit more structually aware per service """
	def fuzz_smarter(self,endpoint,coid):
		"""Fuzzes a specific endpoint based on the provided coid.
		Parameters:
		- endpoint (str): The endpoint to be fuzzed.
		- coid (str): The coid of the endpoint to be fuzzed.
		Returns:
		- None: This function does not return anything.
		Processing Logic:
		- Fuzzes endpoint based on coid.
		- If endpoint is "phone-service", call fuzz_phone_service function.
		- If endpoint is "publisher_channel", call fuzz_publisher_service function."""
		
		if endpoint == "phone-service":
			self.fuzz_phone_service(coid)
		elif endpoint == "publisher_channel":
			self.fuzz_publisher_service(coid)

	""" /services/sys.service.phone/phone-service """
	def fuzz_phone_service(self,coid):
		""""Fuzzes the phone service by sending a random message with a specified client ID."
		Parameters:
		- coid (int): The client ID to be used for the message.
		Returns:
		- None: This function does not return any value.
		Processing Logic:
		- Generates a random message number.
		- Fills the message buffer with 1024 bytes of the character 'D'.
		- Sends the message to the specified client ID."""
		
		data_len = 0x1C 
		low = 0x1000 
		high = 0x9000

		x = ClientMsg()
		x.msg_no = secrets.SystemRandom().randint(low,high)
		self.libc.memset(x.buffer,0x44,1024)
		self.send_sync(coid,x,data_len)

	# First byte 0x20, 0x100, 0x33, 0x728 0x34, 
	def fuzz_publisher_service(self,coid):
		""""Updates the publisher service for the given company ID."
		Parameters:
		- coid (int): The company ID to update the publisher service for.
		Returns:
		- None: This function does not return any value.
		Processing Logic:
		- Calls the publisher service API.
		- Passes the company ID as a parameter.
		- Updates the publisher service for the given company.
		- No error handling is included."""
		
		pass

	""" Base fuzzing function """
	def fuzz_message(self,coid,name):
		""""""
		
		size = self.message_size()
		#size = 16537
		print("++ Fuzzing endpoint ++", name)

		try:
			buf = str(os.urandom(size))
			self.testcase = bytes(buf, 'UTF-8')
		except:
			buf = b"AAAAAAAAAAAAA"
			self.testcase = buf
		
		self.send_sync(coid,buf,len(buf))
		#self.fuzz_pulse(coid)

	def save_testcase(self):
		""""""
		
		print(self.testcase)
		fd = open(self.crash_dir + self.fn + ".bin","wb")
		fd.write(self.testcase)
		fd.close()

	def fuzz_pulse(self,coid):
		""""""
		
		code = secrets.SystemRandom().randint(0,127)
		print ("Pulse code = ", code)
		value = secrets.SystemRandom().randint(0,127)
		ret = self.libc.MsgSendPulse(coid,0,code,value)
		print("Pulse ret = ", ret)
		if ret != -1:
			sys.exit(0)

	def fuzz_loop(self,name):
		""""""
		

		if name != None:
			coid = (self.get_coid(name),name)

		while True:
			# Filename for the testcase to be saved to.
			self.fn = str(secrets.SystemRandom().randint(0,0xffffff))

			if name == None:
				coid = self.random_coid()	
				self.fuzz_message(coid[0],coid[1])
			else:
				print(coid)
				self.fuzz_message(coid[0],coid[1])

			if self.is_simulator:
				if self.is_core_created():
					self.save_testcase()
			else:
				if not self.is_endpoint_ok("/dev/name/local/"+coid[1]):
					print("++ Endpoint seems to have died ++", coid[1])
					self.save_testcase()
					self.squat_endpoint(coid[1])
					sys.exit(0)
			
	# The coid that is exposed to all processes
	def get_procmgr_sidechannel(self):
		""""""
		
		pass
			
	def create_endpoint(self):
		""""""
		
		buf = create_string_buffer(1024)
		self.libc.memset(buf,0x42,1024)
		libc.name_attach(0,buf,0)

	def squat_endpoint(self,endpoint):
		ret = self.libc.name_attach(0,bytes(endpoint, 'UTF-8'),0)
		p = cast(ret,POINTER(_name_attach)).contents
		buf = create_string_buffer(256)
		print("Squatting Endpoint ", p.chid)
		while True:
			print("Receiving Messages")
			rcvid = self.libc.MsgReceive(p.chid, buf, 10, 0)
			print(buf)
			print("After blocking")


	def is_core_created(self):
		arr = glob.glob('/var/log/*.core')
		if len(arr) != 0:
			print("++ Core file has been created ++", arr[0])
			shutil.move(arr[0],self.crash_dir + os.path.basename(arr[0]) + self.fn)
			return True
		return False

	""" Check to see if the endpoint is still there - indicative of crash """
	def is_endpoint_ok(self,endpoint):
		return os.path.exists(endpoint)


if __name__ == "__main__":
	fuzz = IPCFuzz()
	if len(sys.argv) > 1:
		fuzz.fuzz_loop(sys.argv[1])
	else:
		fuzz.fuzz_loop(None)

