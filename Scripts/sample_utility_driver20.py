# DO NOT HARD CODE 

import time
import os
import sys
import subprocess
import pexpect			    #yum install python-pexpect
import re 
import argparse
import colorama                     #yum install python3-colorama python-colorama

#--------------------------------------------------------------------------------------------------
# Configuration
#--------------------------------------------------------------------------------------------------

# Path where all the utils application binaries are present.
#PKP_PATH = "/usr/local/bin/"
PKP_PATH = "/root/n3fips/google/cnn35xx-nfbe-kvm-xen-pf/software/bindist"

# Enable flags to execute coresponding Utility.
test_pkp_blocking = 1
test_pkp_nonblocking = 1
test_crypto = 1
Cfm2test = 1
pkptester = 1
testSSL = 1

#--------------------------------------------------------------------------------------------------

# Enable ciphers to be tested for pkpspeed_blocking Utility
test_rsa_crt = 1			# RSA CRT
test_rsa_non_crt = 1			# RSA
test_Tdes = 1				# 3DES
test_aes = 1				# AES
test_random = 1				# Disable this for fips_state=2
test_fips_random = 1			# FIPS Random
test_ECDHFull = 1			# ECDH Full
test_rc4 = 1				# Disable this for fips_state=2
test_RsaServerFull = 1			# RSA Server full
test_RecordEnc = 1			# Record Encryption

#--------------------------------------------------------------------------------------------------

time_app = 10                           # Time for application to run (in sec)
timeout = 300				# Time out for expect (in sec)
threads_b = 1				# Number of thread for pkpspeed_blocking
threads_nb = 1				# Number of thread for pkpspeed_nonblocking
test_pkp_walk_thr = 0                   # Packet walk through
capture_benchmarks = 0                  # Performance Benchmarks

#--------------------------------------------------------------------------------------------------

ciphers = [ 0, 1, 2]
buf_size = [1, 16, 32, 64, 128, 256, 512, 1024, 2048,3072, 4096, 8196, 16200]
buf_size_b = [1, 16, 32, 64, 128, 256, 512, 1024, 2048,3072, 4096, 8196, 16384]
symm_cipher = ["AES_128", "AES_256", "3DES"]
asym_cipher = ["RSA", "RSA_CRT"]
modulus_size = [1024, 2048, 3072, 4096]
aes_range = [128, 192, 256]
#modulus_size = [2048, 3072]                        #Enable this for fips_state=2 and disable the other corresponding one.
keys = [1024, 2048, 3072, 4096]
#keys = [2048, 3072]				   #Enable this for fips_state=2 and disable the other corresponding one.
curves = ["P192", "P256", "P384"]
#curves = ["P256", "P384"]                          #Enable this for fips_state=2 and disable the other corresponding one.

#--------------------------------------------------------------------------------------------------
# Configuration End
#--------------------------------------------------------------------------------------------------
RSA_NONCRT = "A"
RSA_CRT = "B"
TDES = "C"
AES = "D"
RC4 = "E"
RSA_SERVER_FULL = "F"
RECORD_ENC = "G"
FIPS_RANDOM = "H"
RANDOM = "I"
ECDHFULL = "J"
TOKEN_YES = "y"
STATIC_YES = "y"
TOKEN_NO = "n"
STATIC_NO = "n"


def folder_checks (path) :
#	if not os.path.isfile(path):
#		print ("Pkpspeed app does not exists at ",path)
	print ("In case of timeout, kill the application after the test completion");
	if not os.path.exists(path+"/"+partition_name):
		os.makedirs(path+"/"+partition_name)
		print ("Dir is created: "+path+"/"+partition_name)

	
def rsa_operations ( RSA, size, static ) :
	pkp.sendline (str(RSA))
	try:
		if (RSA == "F"):
			pkp.expect ("Key size", timeout)
		else:
			pkp.expect ("mod size", timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_blocking: Timed out. Check logs")
		return pkp.before
	pkp.sendline (str(size))
	try:
		if (RSA != "F"):
			pkp.expect ("static key", timeout)
			pkp.sendline (static)
			try:
				pkp.expect ("eXit", timeout)
			except pexpect.TIMEOUT:
				print (Fore.RED + "pkpspeed_blocking: Timed out. Check logs")
				return pkp.before
		else:
			pkp.expect ("eXit", timeout)
		return pkp.before
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_blocking: Timed out. Check logs")
		return pkp.before
	pkp.expect ("eXit", timeout)
	return pkp.before


def sym_cipher (CIPHER, pkt_size, key_size):
	pkp.sendline(CIPHER)
	try:
		if (CIPHER == "D"):
			pkp.expect("key", timeout)
			pkp.sendline(key_size)
		if (CIPHER == "A" or CIPHER == "B" or CIPHER == "C" or CIPHER == "D"):
			pkp.expect("size of the packet", timeout)
			pkp.sendline(pkt_size)
		elif (CIPHER == "J"):
			pkp.expect("Curve", timeout)
			pkp.sendline(pkt_size)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_blocking: Timed out. Check logs")
		return pkp.before
	pkp.expect("eXit", timeout)
	return pkp.before

#Record Enc for pkpspeed_blocking
def record_enc (Option, Cipher, key_size, pkt_size):
	pkp.sendline(Option)
	try:
		pkp.expect("Cipher")
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_blocking: Timed out. Check logs")
		return pkp.before
	pkp.sendline(Cipher)
	try:
		if (Cipher != "1"):
			pkp.expect("key")
			pkp.sendline(key_size)
			try:
				pkp.expect("packet")
			except pexpect.TIMEOUT:
				print (Fore.RED + "pkpspeed_blocking: Timed out. Check logs")
				return pkp.before
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_blocking: Timed out. Check logs")
		return pkp.before
	pkp.sendline(pkt_size)
	try:
		pkp.expect("eXit", timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_blocking: Timed out. Check logs")
		return pkp.before
	return pkp.before

	
# pkpspeed_nonblocking
def RunPkpNonBlock_SymCipher (cipher, data_size) :
	pkp_non = pexpect.spawn ("bash")
	pkp_non.logfile = open("./Logs/"+partition_name+"/test_pkp_nonblocking.log", "a")
	pkp_non.sendline (PKP_PATH+"/pkpspeed_nonblocking -pname "+partition_name+" -s crypto_user -p user123")
	try:
		pkp_non.expect ("thread",timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_nonblocking: Symm cipher: Timed out. Check logs")
		pkp_non.logfile.close() 
		return pkp_non.before
	pkp_non.sendline (str(threads_nb))
	try:
		pkp_non.expect ("cipher", timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_nonblocking: Symm cipher: Timed out. Check logs")
		pkp_non.logfile.close() 
		return pkp_non.before
	pkp_non.sendline (cipher)
	try:
		pkp_non.expect ("data size", timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_nonblocking: Symm cipher: Timed out. Check logs")
		pkp_non.logfile.close() 
		return pkp_non.before
	pkp_non.sendline (data_size)
	try:
		pkp_non.expect ("time", timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_nonblocking: Symm cipher: Timed out. Check logs")
		pkp_non.logfile.close() 
		return pkp_non.before
	pkp_non.sendline (str(time_app))
	try:
		pkp_non.expect ('#', timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_nonblocking: Symm cipher: Timed out. Check logs")
		pkp_non.logfile.close() 
		return pkp_non.before
	pkp_non.logfile.close() 
	return pkp_non.before


def RunPkpNonBlock_AsymCipher (cipher, mod_size, static) :
	pkp_non = pexpect.spawn ("bash")
	pkp_non.logfile = open("./Logs/"+partition_name+"/test_pkp_nonblocking.log", "a")
	pkp_non.sendline (PKP_PATH+"/pkpspeed_nonblocking -pname "+partition_name+" -s crypto_user -p user123")
	try:
		pkp_non.expect ("thread",timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_nonblocking: Symm cipher: Timed out. Check logs")
		pkp_non.logfile.close() 
		return pkp_non.before
	pkp_non.sendline (str(threads_nb))
	try:
		pkp_non.expect ("cipher", timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_nonblocking: Symm cipher: Timed out. Check logs")
		pkp_non.logfile.close() 
		return pkp_non.before
	pkp_non.sendline (cipher)
	try:
		pkp_non.expect ("modulus", timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_nonblocking: Symm cipher: Timed out. Check logs")
		pkp_non.logfile.close() 
		return pkp_non.before
	pkp_non.sendline (mod_size)
	try:
		pkp_non.expect ("time", timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_nonblocking: Symm cipher: Timed out. Check logs")
		pkp_non.logfile.close() 
		return pkp_non.before
	pkp_non.sendline (str(time_app))
	try:
		pkp_non.expect ("static key", timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_nonblocking: Symm cipher: Timed out. Check logs")
		pkp_non.logfile.close() 
		return pkp_non.before
	pkp_non.sendline (static)
	try:
		pkp_non.expect ('#', timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpspeed_nonblocking: Symm cipher: Timed out. Check logs")
		pkp_non.logfile.close() 
		return pkp_non.before
	pkp_non.logfile.close() 
	return pkp_non.before

#test_crypto
def test_Cryto ():
	folder_checks ("./Logs")
	crypto = pexpect.spawn("bash")
	crypto.logfile = open ("./Logs/"+partition_name+"/test_crypto.log", "w")
	crypto.sendline (PKP_PATH+"/test_crypto -pname "+partition_name+"  -verbose -s crypto_user -p user123")
	try:
		crypto.expect ('ECDSA: ', timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "test_crypto: Timed out. Check logs")
		crypto.logfile.close() 
		return crypto.before
	crypto.logfile.close() 
	return crypto.before

#Cfm2Test
def cfm2test ():
	folder_checks ("./Logs")
	test_cfm2test = pexpect.spawn("bash")
	test_cfm2test.logfile = open ("./Logs/"+partition_name+"/test_cfm2test.log", "w")
	test_cfm2test.sendline(PKP_PATH+"/Cfm2Test -pname "+partition_name+" -s crypto_user -p user123")
	try:
		test_cfm2test.expect('Test Utility finished with result code',timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "cfm2test: Timed out. Check logs")
		test_cfm2test.logfile.close() 
		return test_cfm2test.before
	test_cfm2test.logfile.close() 
	return test_cfm2test.before


#pkpTester
def pkpTester ():
	folder_checks ("./Logs")
	test_pkpTester = pexpect.spawn("bash")
	test_pkpTester.logfile = open ("./Logs/"+partition_name+"/test_pkpTester.log", "w")
	test_pkpTester.sendline(PKP_PATH+"/pkpTester -pname "+partition_name+" -s crypto_user -p user123")
	try:
		test_pkpTester.expect('Random.*number.*generation.*non-blocking',timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "pkpTester: Timed out. Check logs")
		test_pkpTester.logfile.close()
		return test_pkpTester.before
	test_pkpTester.logfile.close()
	return test_pkpTester.before

#test_ssl
def test_ssl ():
	folder_checks ("./Logs")
	test_ssl = pexpect.spawn("bash")
	test_ssl.logfile = open ("./Logs/"+partition_name+"/test_testSSL.log", "w")
	test_ssl.sendline(PKP_PATH+"/test_ssl -pname "+partition_name+" -s crypto_user -p user123")
	try:
		test_ssl.expect('Client.*Authenticated.*Handshake:',timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "test_ssl Check 1: Timed out. Check logs")
	test_ssl.sendline(" ")
	try:
		test_ssl.expect('Comparing.*Encrypted.*Server.*Finished.*messages',timeout)
	except pexpect.TIMEOUT:
		print (Fore.RED + "test_ssl Check 2: Timed out. Check logs")
		test_ssl.logfile.close()
		return test_ssl.before
	test_ssl.logfile.close()
	return test_ssl.before

def avg_perf_ops (log):
	regex = r"OPERATIONS/second.*"
	count = sum(1 for x in re.finditer(regex, log))
	total_number_of_operations = 0;
	total_ops = re.findall(regex, log)
	for ops in total_ops:
		matches = re.findall(r'\d+', ops)
		total_number_of_operations = total_number_of_operations + int(matches[0])
	avg_ops = total_number_of_operations/count
	return avg_ops

def cal_perf (log, option):
	if option == "A":                    # Option to calculate average operations per second
		ops = avg_perf_ops(log)
		return ops
	elif option == "B":		     # To get Bandwidth per second from pkpspeed_nonblocking
		regex = r"Bandwidth.*"
		total_ops = re.findall(regex, log)
		match = re.findall(r'\d+', str(total_ops))
		return match[0]
	elif option == "C":		     # To get operations per second from pkpspeed_nonblocking		    
		regex = r"operations/second.*"
		total_ops = re.findall(regex, log)
		match = re.findall(r'\d+', str(total_ops))
		return match[0]

	else: 				     # To calculate the throughput
		ops = avg_perf_ops(log)
		throughput = ((( ops * int(option) * 8 )/ 1024 ) /1024 )
		return throughput


from colorama import Fore, Back, Style
colorama.init()

parser = argparse.ArgumentParser(description='Automation test suite for N3FIPS utils application')
parser.add_argument('-p','--pname', help='Partition Name', required=True)
args = vars(parser.parse_args())
partition_name = args ['pname'] 

if (test_pkp_blocking) :
	folder_checks ("./Logs")
	#folder_checks (PKP_PATH+"/pkpspeed_blocking")
	pkp = pexpect.spawn (PKP_PATH+"/pkpspeed_blocking -pname "+partition_name+" -s crypto_user -p user123")
	pkp.logfile = open("./Logs/"+partition_name+"/test_pkp_blocking.log", "w")
	if (capture_benchmarks) :
		perf_log = open("./Logs/"+partition_name+"/perf_pkp_blocking.log", "w")
	pkp.expect ("MAX",timeout)
	pkp.sendline (str(threads_b))
	pkp.expect ("time", timeout)
	pkp.sendline (str(time_app))
	pkp.expect ("eXit", timeout)
	

	if (test_rsa_crt) :
		for mod_size in modulus_size :
			result = rsa_operations (RSA_CRT, mod_size, STATIC_YES)
			if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
				print (Fore.RED + "RSA_CRT failed")
			elif ("OPERATIONS/second" in result):
				print (Fore.GREEN + "RSA_CRT using static key "+str(mod_size)+" passed")
				if (capture_benchmarks) :
					average_ops = cal_perf (result, "A")
					perf_log.write("RSA_CRT using static key : "+str(threads_b)+" : "+str(mod_size)+" : "+str(average_ops) + "\n")
			else :
				print (Fore.RED + "RSA_CRT failed")
			
			result = rsa_operations (RSA_CRT, mod_size, STATIC_NO)
			if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
				print (Fore.RED + "RSA_CRT failed")
			elif ("OPERATIONS/second" in result):
				print (Fore.GREEN + "RSA_CRT "+str(mod_size)+" passed")
				if (capture_benchmarks) :
					average_ops = cal_perf (result, "A")
					perf_log.write("RSA_CRT : "+str(threads_b)+" : "+str(mod_size)+" : "+str(average_ops) + "\n")
			else :
				print (Fore.RED + "RSA_CRT failed. Check logs")
	
	if (test_rsa_non_crt) :
		for mod_size in modulus_size :
			result = rsa_operations (RSA_NONCRT, mod_size, STATIC_YES)
			if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
				print (Fore.RED + "RSA_NON-CRT failed")
			elif ("OPERATIONS/second" in result):
				print (Fore.GREEN + "RSA NON-CRT using static key "+str(mod_size)+" passed")
				if (capture_benchmarks) :
					average_ops = cal_perf (result, "A")
					perf_log.write("RSA using static key: "+str(threads_b)+" : "+str(mod_size)+" : "+str(average_ops)+"\n")
			else :
				print (Fore.RED + "RSA_NON-CRT failed")

			result = rsa_operations (RSA_NONCRT, mod_size, STATIC_NO)
			if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
				print (Fore.RED + "RSA_NON-CRT failed")
			elif ("OPERATIONS/second" in result):
				print (Fore.GREEN + "RSA NON-CRT "+str(mod_size)+" passed")
				if (capture_benchmarks) :
					average_ops = cal_perf (result, "A")
					perf_log.write("RSA : "+str(threads_b)+" : "+str(mod_size)+" : "+str(average_ops)+"\n")
			else :
				print (Fore.RED + "RSA_NON-CRT failed")


	if (test_Tdes) :
		if (test_pkp_walk_thr):
			for pkt_size in range (1,16384,1):
				result = sym_cipher (TDES, str(pkt_size), 0)
				if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
					print (Fore.RED + "TDES failed")
				elif ("OPERATIONS/second" in result):
					print (Fore.GREEN + "TDES "+str(pkt_size)+" passed")
				else :
					print (Fore.RED + "TDES failed")

		else :
			for pkt_size in buf_size_b:
				result = sym_cipher (TDES, str(pkt_size), 0)
				if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
					print (Fore.RED + "TDES failed")
				elif ("OPERATIONS/second" in result):
					print (Fore.GREEN + "TDES "+str(pkt_size)+" passed")
					if (capture_benchmarks) :
						Mbps = cal_perf (result, pkt_size)
						perf_log.write("3DES-CBC : "+str(threads_b)+" : "+str(pkt_size)+" : "+str(Mbps)+"\n")
				else :
					print (Fore.RED + "TDES failed")

	
	if (test_aes) :
		for key_size in aes_range:
			if (test_pkp_walk_thr) :
				for pkt_size in range (1,16384,1):
					result = sym_cipher (AES, str(pkt_size), str(key_size))
					if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
						print (Fore.RED + "AES failed")
					elif ("OPERATIONS/second" in result):
						print (Fore.GREEN + "AES "+str(key_size)+" "+str(pkt_size)+" passed")
					else :
						print (Fore.RED + "AES failed")

			else:
				for pkt_size in buf_size_b:
					result = sym_cipher (AES, str(pkt_size), str(key_size))
					if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
						print (Fore.RED + "AES failed")
					elif ("OPERATIONS/second" in result):
						print (Fore.GREEN + "AES "+str(key_size)+" "+str(pkt_size)+" passed")
						if (capture_benchmarks) :
							Mbps = cal_perf (result, pkt_size)
							perf_log.write("AES "+ str(key_size)+" : "+str(threads_b)+" : "+str(pkt_size)+" : "+str(Mbps)+"\n")
					else :
						print (Fore.RED + "AES failed")
	
	if (test_rc4) :
		result = sym_cipher (RC4, str(0), str(0))
		if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
			print (Fore.RED + "RC4 failed")
		elif ("OPERATIONS/second" in result):
			print (Fore.GREEN + "RC4 passed")
			if (capture_benchmarks) :
				average_ops = cal_perf (result, "A")
				perf_log.write("RC4 : "+str(threads_b)+" : "+str(average_ops)+"\n")
		else :
			print (Fore.RED + "RC4 failed")

	if (test_random) :
		result = sym_cipher (RANDOM, str(0), str(0))
		if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
			print (Fore.RED + "RANDOM failed")
		elif ("OPERATIONS/second" in result):
			print (Fore.GREEN + "RANDOM passed")
			if (capture_benchmarks) :
				average_ops = cal_perf (result, "A")
				perf_log.write("RANDOM : "+str(threads_b)+" : "+str(average_ops)+"\n")
		else :
			print (Fore.RED + "RANDOM failed")

	if (test_fips_random) :
		result = sym_cipher (FIPS_RANDOM, str(0), str(0))
		if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
			print (Fore.RED + "FIPS_RANDOM failed")
		elif ("OPERATIONS/second" in result):
			print (Fore.GREEN + "FIPS_RANDOM passed")
			if (capture_benchmarks) :
				average_ops = cal_perf (result, "A")
				perf_log.write("FIPS_RANDOM : "+str(threads_b)+" : "+str(average_ops)+"\n")
		else :
			print (Fore.RED + "FIPS_RANDOM failed")


	if (test_ECDHFull) :
		for curve in curves:
			result = sym_cipher (ECDHFULL, str(curve), 0)
			if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
				print (Fore.RED + "ECDH failed")
			elif ("OPERATIONS/second" in result):
				print (Fore.GREEN + "ECDH "+str(curve)+" passed")
				if (capture_benchmarks) :
					average_ops = cal_perf (result, "A")
					perf_log.write("ECDHFull : "+str(threads_b)+" : "+str(curve)+" : "+str(average_ops)+"\n")
			else :
				print (Fore.RED + "ECDH failed")

	if (test_RsaServerFull) :
		for key in keys:
			result = rsa_operations (RSA_SERVER_FULL, str(key), 0)
			if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
				print (Fore.RED + "RSA Server Full failed")
			elif ("OPERATIONS/second" in result):
				print (Fore.GREEN + "RSA Server Full "+str(key)+" passed")
				if (capture_benchmarks) :
					average_ops = cal_perf (result, "A")
					perf_log.write("RSAServerFull : "+str(threads_b)+" : "+str(key)+" : "+str(average_ops)+"\n")
			else :
				print (Fore.RED + "RSA Server Full failed")

	if (test_RecordEnc) :
		for cipher_type in ciphers:
			if cipher_type != 1:
				keys = [128, 256]
			else: 
				keys = [128]
			for key_size in keys:
				if (test_pkp_walk_thr) :
					for pkt_size in range (1,16384,1):
						result = record_enc (RECORD_ENC, str(cipher_type), str(key_size), str(pkt_size))
						if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
							print (Fore.RED + "Record Enc failed")
						elif ("OPERATIONS/second" in result):
							if (cipher_type != 1):
								print (Fore.GREEN + "Record Enc "+str(cipher_type)+" "+str(key_size)+" "+str(pkt_size)+" passed")
							else: 
								print (Fore.GREEN + "Record Enc "+str(cipher_type)+" "+str(pkt_size)+" passed")
		
						else :
							print (Fore.RED + "Record Enc failed")

				else:
					for pkt_size in buf_size_b:
						result = record_enc (RECORD_ENC, str(cipher_type), str(key_size), str(pkt_size))
						if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
							print (Fore.RED + "Record Enc failed")
						elif ("OPERATIONS/second" in result):
							if (cipher_type != 1):
								print (Fore.GREEN + "Record Enc "+str(cipher_type)+" "+str(key_size)+" "+str(pkt_size)+" passed")
								if (capture_benchmarks) :
									Mbps = cal_perf (result, pkt_size)
									perf_log.write("Record Enc "+str(cipher_type)+" "+str(key_size)+" : "+str(threads_b)+" : "+str(pkt_size)+" : "+str(Mbps)+"\n")
							else:
								print (Fore.GREEN + "Record Enc "+str(cipher_type)+" "+str(pkt_size)+" passed")
								if (capture_benchmarks) :
									Mbps = cal_perf (result, pkt_size)
									perf_log.write("Record Enc "+str(cipher_type)+" : "+str(threads_b)+" : "+str(pkt_size)+" : "+str(Mbps)+"\n")
						else :
							print (Fore.RED + "Record Enc failed")
	
	pkp.logfile.close()
	with open("./Logs/"+partition_name+"/test_pkp_blocking.log") as f:
		contents = f.read()
		if  ("fail" in contents) or ("error" in contents) or ("Fail" in contents) or ("Error" in contents) or ("Can not" in contents) or ("ERROR" in contents):
			print (Fore.RED + "pkpspeed_blocking failed")
	f.close()
	if (capture_benchmarks) :
		perf_log.close

if (test_pkp_nonblocking) :
	folder_checks ("./Logs")
	if (capture_benchmarks) :
		perf_log_nb = open("./Logs/"+partition_name+"/perf_pkp_nonblocking.log", "w")
	for cipher in symm_cipher :
		for data_size in buf_size : 
			result = RunPkpNonBlock_SymCipher (cipher, str(data_size))
			if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
				print (Fore.RED + cipher+"failed")
			elif ("Bandwidth" in result):
				print (Fore.GREEN + "Symm Cipher: "+cipher+" Data Size: "+str(data_size)+" passed")
				if (capture_benchmarks) :
					Mbps = cal_perf (result, "B")
					perf_log_nb.write("Symm Cipher: "+cipher+" : "+str(data_size)+" : "+Mbps+"\n")
			else :
				print (Fore.RED + cipher+"failed")


	for cipher in asym_cipher :
		for mod_size in modulus_size :
			result = RunPkpNonBlock_AsymCipher (cipher, str(mod_size), STATIC_YES)
			if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
				print (Fore.RED + cipher+ "failed")
			elif ("operations/second" in result):
				print (Fore.GREEN + "Asym Cipher using static key: "+cipher+" ModSize: "+str(mod_size)+" passed")
				if (capture_benchmarks) :
					ops = cal_perf (result, "C")
					perf_log_nb.write("Asym Cipher using static key: "+cipher+" : "+str(mod_size)+" : " +str(ops)+"\n")
			else :
				print (Fore.RED + cipher+ "failed")

			result = RunPkpNonBlock_AsymCipher (cipher, str(mod_size), STATIC_NO)
			if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
				print (Fore.RED + cipher+ "failed")
			elif ("operations/second" in result):
				print (Fore.GREEN + "Asym Cipher: "+cipher+" ModSize: "+str(mod_size)+" passed")
				if (capture_benchmarks) :
					ops = cal_perf (result, "C")
					perf_log_nb.write("Asym Cipher: "+cipher+" : "+str(mod_size)+" : " +str(ops)+"\n")
			else :
				print (Fore.RED + cipher+ "failed")


	#Check for Errors in log file
	with open("./Logs/"+partition_name+"/test_pkp_nonblocking.log") as f:
		contents = f.read()
		if  ("fail" in contents) or ("error" in contents) or ("Fail" in contents) or ("Error" in contents) or ("Can not" in contents) or ("ERROR" in contents):
			print (Fore.RED + "pkpspeed_nonblocking failed")
	f.close()
	
	if (capture_benchmarks) :
		perf_log_nb.close()

if (test_crypto):
	result = test_Cryto ()
	if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
		print (Fore.RED + "test_crypto failed")
		#print (" Log : ", result)
	else :
		print (Fore.GREEN + "Test_crypto passed")
	#Check for Errors in log file
	with open ("./Logs/"+partition_name+"/test_crypto.log") as f:
		contents = f.read()
		if  ("fail" in contents) or ("error" in contents) or ("Fail" in contents) or ("Error" in contents) or ("Can not" in contents) or ("ERROR" in contents):
			print (Fore.RED + "test_crypto failed")
	f.close() 


if (Cfm2test) :
	result = cfm2test ()
	if  ("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result):
		print (Fore.RED + "Cfm2Test failed") 
		#print (" Log : ", result)
	else :
		print (Fore.GREEN + "Cfm2Test passed")
	#Check for Errors in log file
	with open ("./Logs/"+partition_name+"/test_cfm2test.log") as f:
		contents = f.read()
		if  ("fail" in contents) or ("error" in contents) or ("Fail" in contents) or ("Error" in contents) or ("Can not" in contents) or ("ERROR" in contents):
			print (Fore.RED + "test_cfm2test failed")
	f.close() 

if (pkptester == 1) :
	result = pkpTester ()
	with open("./Logs/"+partition_name+"/test_pkpTester.log") as f:
		contents = f.read()
	        count = sum(1 for x in re.finditer(r"\OK\b", contents))
		if  ("fail" in contents) or ("error" in contents) or ("Fail" in contents) or ("Error" in contents) or ("Can not" in contents) or ("ERROR" in contents):
			print (Fore.RED + "pkpTester failed")

	if count != 6 or (("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result)):
		print (Fore.RED + "pkpTester failed")
		#print (" Log : ", result)
	else :
		print (Fore.GREEN + "pkpTester passed")
	f.close()


if (testSSL == 1) :
	result = test_ssl ()
	with open("./Logs/"+partition_name+"/test_testSSL.log") as f:
		contents = f.read()
	        count = sum(1 for x in re.finditer(r"\Done\b", contents))
		if  ("fail" in contents) or ("error" in contents) or ("Fail" in contents) or ("Error" in contents) or ("Can not" in contents) or ("ERROR" in contents):
			print (Fore.RED + "TestSSL failed")

	if count != 30 or (("fail" in result) or ("error" in result) or ("Fail" in result) or ("Error" in result) or ("Can not" in result)):
		print (Fore.RED + "testSSL failed")
		#print (" Log : ", result)
	else :
		print (Fore.GREEN + "testSSL passed")
	f.close()
