#! /usr/bin/env python3
"""
Benchmarking script for comparing different cryptographic algorithms:
	1) Hashing: SHA-256, BLAKE2b
	2) Symmetric Encryption: AES, ChaCha20
	3) Asymmetric (Hybrid): RSA, ECC
	4) Post-Quantum: Kyber

Metrics Measured:
	1) Execution Time
	2) Peak Memory Usage
	3) Throughput (MB/s)
	4) Correctness and Tampering Validation

Author: Phyu Phyu Shinn Thant - Zyra (S4022136)
Course: Security in Computing and IT
University: RMIT University Vietnam
"""
# Library Imports
import os
import time
import secrets
import tracemalloc
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from cryptography.hazmat.primitives import serialization, hashes, hmac, kdf
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import numpy as np
import csv
from tabulate import tabulate

# Environment Setup
try:
	from pqct import PostQuantumCryptoToolkit
	toolkit = PostQuantumCryptoToolkit()
	KYBER_AVAILABLE = True
except ImportError:
	KYBER_AVAILABLE = False
	print("Kyber not available. PQC tests will be skipped.")

# Configurations
DATA_SIZES = [1024, 10_240, 102_400, 1_048_576] # 1KB to 1MB
RUNS = 5

# Security Mapping
SECURITY_MAP = {
	'SHA-256': '256-bit',
	'SHA-512': '512-bit',
	'BLAKE2b-512': '512-bit',
	'AES-128': '128-bit',
	'AES-256': '256-bit',
	'ChaCha20-Poly1305': '256-bit',
	'RSA-2048': '112-bit',
	'ECC-384': '192-bit',
	'Kyber': 'Post-Quantum'
}

# Utilities

def generate_data(size):
	"""
    Generate random data with a specific size.
    """
	return secrets.token_bytes(size)


def benchmark(operation_name, data_size, func, *args):
	"""
	Benchmarking Test for the algorithms
	Params:
		operation_name = name of the operation, not for the function but for the tabulate
        data_size = size of the data
        func = function call for the algorithm
		args = Arguments to be passed through the func
	Returns: Benchmark metrics (Mean time, Std time, Throughput, Mean memory), and the result of the function call.
	"""
	times = []
	memories = []
	result = None

	for _ in range(RUNS):
		tracemalloc.start()
		start = time.perf_counter()

		result = func(*args)

		end = time.perf_counter()
		current, peak = tracemalloc.get_traced_memory()
		tracemalloc.stop()

		times.append(end - start)
		memories.append(peak / (1024 * 1024)) # Convert to MB

	mean_time = np.mean(times)
	std_time = np.std(times)
	throughput = (data_size / 1024 / 1024) / mean_time if mean_time > 0 else 0
	mean_mem = np.mean(memories)

	return (mean_time, std_time, throughput, mean_mem), result


# Validation Functions

def validate_decryption_integrity(original_data, decrypted_data, algorithm_name):
	"""
    Checks if the decrypted data matches the original data.
    Params:
        original_data = the original data before encryption
        decrypted_data = the data after decryption
        algorithm_name = the name of the algorithm
    Return: True/False
    """
	is_valid = original_data == decrypted_data
	print(f"  [{algorithm_name}]: Decryption Integrity Check: {'PASS' if is_valid else 'FAIL'}")
	return is_valid

def tamper_check(data, key, nonce, algorithm_name, mode):
	"""
    Checks the failure of authenticated encryption (AEAD) to see if the cipher is tampered with one flipped byte
	Params:
        data, key, nonce, algorithm, mode
    Return: print statement to indicate success or failure
	"""
	if mode == 'aes':
		cipher_aes = AESGCM(key)
		ct_tag = cipher_aes.encrypt(nonce, data, None)
		ciphertext = ct_tag[:-16]
		tag = ct_tag[-16:]

	elif mode == 'chacha':
		cipher_chacha = ChaCha20Poly1305(key)
		ct_tag = cipher_chacha.encrypt(nonce, data, None)
		ciphertext = ct_tag[:-16]
		tag = ct_tag[-16:]
	else:
		return

	# Tamper the ciphertext (flip one byte)
	tampered_ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0x01])
	tampered_ct_tag = tampered_ciphertext + tag

	# Attempt decryption with tampered ciphertext
	try:
		if mode == 'aes':
			AESGCM(key).decrypt(nonce, tampered_ct_tag, None)
		elif mode == 'chacha':
			ChaCha20Poly1305(key).decrypt(nonce, tampered_ct_tag, None)

		print(f"  [{algorithm_name}]: Ciphertext Tamper Check: FAIL - Decryption succeeded")
	except Exception:
		print(f"  [{algorithm_name}]: Ciphertext Tamper Check: PASS - Decryption failed as expected")

	# Tamper the tag (flip one byte)
	tampered_tag = tag[:-1] + bytes([tag[-1] ^ 0x01])
	tampered_tag_ct_tag = ciphertext + tampered_tag

	# Attempt decryption with tampered tag
	try:
		if mode == 'aes':
			AESGCM(key).decrypt(nonce, tampered_tag_ct_tag, None)
		elif mode == 'chacha':
			ChaCha20Poly1305(key).decrypt(nonce, tampered_tag_ct_tag, None)

		print(f"  [{algorithm_name}]: Tag Tamper Check: FAIL - Decryption succeeded")
	except Exception:
		print(f"  [{algorithm_name}]: Tag Tamper Check: PASS - Decryption failed as expected")

def avalanche_test(data, hash_func, algorithm_name):
	"""
    Avalanche test with a flip bit
    Params: 
        data, hash_func, algorithm_name
    Return: True/False
    """
	original_hash = hash_func(data)

	# Flip a single bit in the original data
	flipped_data = bytearray(data)
    # XOR with 1 to flip the least significant bit
	flipped_data[5] = flipped_data[5] ^ 0x01
	flipped_hash = hash_func(bytes(flipped_data))

	# Calculate Hamming Distance
	diff_bits = 0
	for byte_orig, byte_flip in zip(original_hash, flipped_hash):
		diff_bits += bin(byte_orig ^ byte_flip).count('1')

	total_bits = len(original_hash) * 8
	flipped_percentage = (diff_bits / total_bits) * 100

	print(f"  [{algorithm_name}]: Avalanche Effect Test:")
	print(f"    - Total bits in digest: {total_bits}")
	print(f"    - Flipped bits: {diff_bits} ({flipped_percentage:.2f}%)")
	return flipped_percentage > 49.0


# Algorithm Implementations
# Hashing
def sha_hash(data, digest_size=256):
    if digest_size == 256:
        return hashlib.sha256(data).digest()
    elif digest_size == 512:
        return hashlib.sha512(data).digest()
    else:
        raise ValueError("Unsupported digest size")


def blake2b_hash(data, digest_size=512):
    return hashlib.blake2b(data).digest()


# Symmetric Algorithms
def aes_encryption(data, key, nonce):
	cipher = AESGCM(key)
	ct_tag = cipher.encrypt(nonce, data, None)
	return ct_tag[:-16], ct_tag[-16:]


def aes_decryption(ciphertext, tag, key, nonce):
	try:
		# Decrypts and Authenticate
		cipher = AESGCM(key)
		ct_tag = ciphertext + tag
		return cipher.decrypt(nonce, ct_tag, None)
	except Exception as e:
		raise ValueError(f"AES Decryption/Authentication failed: {e}")


def chacha20_encryption(data, key, nonce):
	cipher = ChaCha20Poly1305(key)
	# Encrypt
	ct_tag = cipher.encrypt(nonce, data, None)
	return ct_tag[:-16], ct_tag[-16:]


def chacha20_decryption(ciphertext, tag, key, nonce):
	try:
		# Decrypts and Authenticate
		cipher = ChaCha20Poly1305(key)
		ct_tag = ciphertext + tag
		return cipher.decrypt(nonce, ct_tag, None)
	except Exception as e:
		raise ValueError(f"ChaCha20 Decryption/Authentication failed: {e}")


# Asymmetric Algorithms (Hybrid Encryption)
def rsa_hybrid_encryption(data, rsa_public_key, aes_key_size=32, aes_nonce=os.urandom(12)):
	aes_key = os.urandom(aes_key_size)
	(ciphertext, tag) = aes_encryption(data, aes_key, aes_nonce)
	key_package = aes_key + aes_nonce + tag
	encrypted_key_package = rsa_public_key.encrypt(key_package, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
	return encrypted_key_package, ciphertext, tag


def rsa_hybrid_decryption(encrypted_key_package, ciphertext, tag, rsa_private_key, aes_key_size=32):
	key_package = rsa_private_key.decrypt(encrypted_key_package, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
	aes_key = key_package[:aes_key_size]
	aes_nonce = key_package[aes_key_size:aes_key_size + 12]
	return aes_decryption(ciphertext, tag, aes_key, aes_nonce)


def ecc_hybrid_encryption(data, ecc_peer_public_key, ecc_private_key, aes_key_size=32, aes_nonce=os.urandom(12)):
	shared_secret = ecc_private_key.exchange(ec.ECDH(), ecc_peer_public_key)
	hkdf = HKDF(algorithm=hashes.SHA256(), length=aes_key_size, salt=None, info=b'ecc-hybrid-encrypt', backend=default_backend())
	aes_key = hkdf.derive(shared_secret)
	(ciphertext, tag) = aes_encryption(data, aes_key, aes_nonce)
	return ciphertext, aes_nonce, tag


def ecc_hybrid_decryption(ciphertext, nonce, tag, ecc_peer_public_key, ecc_private_key, aes_key_size=32):
	shared_secret = ecc_private_key.exchange(ec.ECDH(), ecc_peer_public_key)
	hkdf = HKDF(algorithm=hashes.SHA256(), length=aes_key_size, salt=None, info=b'ecc-hybrid-encrypt', backend=default_backend())
	aes_key = hkdf.derive(shared_secret)
	return aes_decryption(ciphertext, tag, aes_key, nonce)


# Asymmetric (Signatures)
def rsa_signing(data, private_key):
	signature = private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
	return signature


def rsa_verification(data, signature, public_key):
	try:
		public_key.verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
		return True
	except InvalidSignature:
		return False


def ecc_signing(data, private_key):
	signature  = private_key.sign(data, ec.ECDSA(hashes.SHA384()))
	return signature


def ecc_verification(data, signature, public_key):
	try:
		public_key.verify(signature, data, ec.ECDSA(hashes.SHA384()))
		return True
	except InvalidSignature:
		return False


def kyber_encryption(data):
	plaintext = np.frombuffer(data, dtype=np.uint16) % 3329
	ciphertext = toolkit.encrypt('kyber', plaintext)
	return ciphertext


def kyber_decryption(ciphertext, private_key):
	decrypted_plaintext = toolkit.decrypt('kyber', ciphertext, private_key)
	return decrypted_plaintext


# Main
def main():
	# Store Results
	results_key_gen = []
	results_throughput = []

	# -------------------------------------------------------------------
	# KEY GENERATION AND SETUP

	print("\n" + "-"*50)
	print("INITIAL KEY GENERATION AND SETUP")
	print("-"*50)

	# Symmetric Keys
	aes_256_key = os.urandom(256 // 8)
	aes_128_key = os.urandom(128 // 8)
	aes_nonce = os.urandom(12)
	chacha_key = os.urandom(256 // 8)
	chacha_nonce = os.urandom(12)
	print(f"Symmetric Keys Generated for AES-256 and ChaCha20.")
	print(f"  AES-GCM Nonce Size: {len(aes_nonce)} bytes (Correct for GCM)")
	print(f"  ChaCha20 Nonce Size: {len(chacha_nonce)} bytes (Correct for ChaCha20 AEAD)")
	print("-" * 50)


	# -------------------------------------------------------------------
	# KEY GENERATION BENCHMARKS
	print("\n" + "-"*50)
	print("ASYMMETRIC KEY GENERATION TIMING")
	print("-"*50)

	# RSA Key Generation
	def gen_rsa_2048():
		return rsa.generate_private_key(public_exponent=65537, key_size=2048)
	metrics, rsa_2048_priv = benchmark("key_gen", 0, gen_rsa_2048)
	rsa_2048_pub = rsa_2048_priv.public_key()
	results_key_gen.append(["RSA-2048", "Key Gen", metrics[0], SECURITY_MAP['RSA-2048']])

	# ECC Key Generation
	def gen_ecc_384():
		return ec.generate_private_key(ec.SECP384R1())
	metrics, ecc_384_priv_A = benchmark("key_gen", 0, gen_ecc_384)
	ecc_384_pub_A = ecc_384_priv_A.public_key()
	ecc_384_priv_B = ec.generate_private_key(ec.SECP384R1())
	ecc_384_pub_B = ecc_384_priv_B.public_key()
	results_key_gen.append(["ECC-384", "Key Gen", metrics[0], SECURITY_MAP['ECC-384']])

	# Kyber Key Generation
	if KYBER_AVAILABLE:
		def gen_kyber():
			return toolkit.supported_algorithms['kyber'].generate_keypair()
		metrics, (kyber_pub, kyber_priv) = benchmark("key_gen", 0, gen_kyber)
		results_key_gen.append(["Kyber", "Key Gen", metrics[0], SECURITY_MAP['Kyber']])
	else:
		kyber_pub, kyber_priv = None, None

	# Print Key Generation Results
	print(tabulate(results_key_gen, headers=["Variant", "Operation", "Mean Time (s)", "Security Level"], floatfmt=".8f"))


	# -------------------------------------------------------------------
	# SECURITY VALIDATION CHECKS - 1KB
	print("\n" + "-"*50)
	print("SECURITY VALIDATION (Data Size: 1KB)")
	print("-"*50)
	data_1kb = generate_data(1024)

	print("\nDecryption Integrity Check")

	# AES-256 GCM
	ct_aes, tag_aes = aes_encryption(data_1kb, aes_256_key, aes_nonce)
	dec_aes = aes_decryption(ct_aes, tag_aes, aes_256_key, aes_nonce)
	validate_decryption_integrity(data_1kb, dec_aes, "AES-256 GCM")

	# ChaCha20
	ct_chacha, tag_chacha = chacha20_encryption(data_1kb, chacha_key, chacha_nonce)
	dec_chacha = chacha20_decryption(ct_chacha, tag_chacha, chacha_key, chacha_nonce)
	validate_decryption_integrity(data_1kb, dec_chacha, "ChaCha20-Poly1305")

	print("\nAEAD Tamper Check")
	tamper_check(data_1kb, aes_256_key, aes_nonce, "AES-256 GCM", 'aes')
	tamper_check(data_1kb, chacha_key, chacha_nonce, "ChaCha20-Poly1305", 'chacha')

	print("\nHashing Avalanche Effect Check")
	avalanche_test(data_1kb, lambda d: sha_hash(d, 256), "SHA-256")
	avalanche_test(data_1kb, lambda d: blake2b_hash(d, 512), "BLAKE2b-512")

	print("\nWrong Key/Tag/Signature Check")
	# Wrong Key Test (AES)
	wrong_key = os.urandom(32)
	try:
		# Decrypting with Wrong Key
		aes_decryption(ct_aes, tag_aes, wrong_key, aes_nonce)
		# Failure Case
		print("  [AES-256]: Wrong Key Check: FAIL - Decryption succeeded")
	except ValueError:
		# Success Case
		print("  [AES-256]: Wrong Key Check: PASS - Decryption failed as expected")

	# Tampered Signature Test (RSA)
	rsa_sig = rsa_signing(data_1kb, rsa_2048_priv)
	tampered_sig = rsa_sig[:-1] + bytes([rsa_sig[-1] ^ 0x01])
	try:
		rsa_verification(data_1kb, tampered_sig, rsa_2048_pub)
		print("  [RSA Sig]: Tampered Signature Check: FAIL - Verification succeeded")
	except Exception:
		print("  [RSA Sig]: Tampered Signature Check: PASS - Verification failed as expected")


	# -------------------------------------------------------------------
	# MAIN THROUGHPUT BENCHMARKS
	print("\n" + "-"*50)
	print("CRYPTOGRAPHIC THROUGHPUT BENCHMARKS")
	print("-"*50)

	# Benchmarks for different data sizes
	for size in DATA_SIZES:
		print(f"\nBenchmark with Data Size: {size} bytes")
		data = generate_data(size)

		# Hashing SHA
		metrics, _ = benchmark("hash", size, sha_hash, data, 256)
		results_throughput.append(["SHA", "SHA-256", "Hash", size] + list(metrics) + [SECURITY_MAP['SHA-256'], "-"])
		metrics, _ = benchmark("hash", size, sha_hash, data, 512)
		results_throughput.append(["SHA", "SHA-512", "Hash", size] + list(metrics) + [SECURITY_MAP['SHA-512'], "-"])

		# Hashing BLAKE2b
		metrics, _ = benchmark("hash", size, blake2b_hash, data, 512)
		results_throughput.append(["BLAKE2b", "BLAKE2b-512", "Hash", size] + list(metrics) + [SECURITY_MAP['BLAKE2b-512'], "-"])

		# Symmetric AES-128
		metrics, (ct_aes_128, tag_aes_128) = benchmark("encrypt", size, aes_encryption, data, aes_128_key, aes_nonce)
		results_throughput.append(["AES (AEAD)", "AES-128 GCM", "Encrypt", size] + list(metrics) + [SECURITY_MAP['AES-128'], len(ct_aes_128)])
		metrics, _ = benchmark("decrypt", size, aes_decryption, ct_aes_128, tag_aes_128, aes_128_key, aes_nonce)
		results_throughput.append(["AES (AEAD)", "AES-128 GCM", "Decrypt", size] + list(metrics) + [SECURITY_MAP['AES-128'], len(ct_aes_128)])

		# Symmetric AES-256 GCM
		metrics, (ct_aes, tag_aes) = benchmark("encrypt", size, aes_encryption, data, aes_256_key, aes_nonce)
		results_throughput.append(["AES (AEAD)", "AES-256 GCM", "Encrypt", size] + list(metrics) + [SECURITY_MAP['AES-256'], len(ct_aes)])
		metrics, _ = benchmark("decrypt", size, aes_decryption, ct_aes, tag_aes, aes_256_key, aes_nonce)
		results_throughput.append(["AES (AEAD)", "AES-256 GCM", "Decrypt", size] + list(metrics) + [SECURITY_MAP['AES-256'], len(ct_aes)])

		# Symmetric ChaCha20
		metrics, (ct_chacha, tag_chacha) = benchmark("encrypt", size, chacha20_encryption, data, chacha_key, chacha_nonce)
		results_throughput.append(["ChaCha20 (AEAD)", "ChaCha20-Poly1305", "Encrypt", size] + list(metrics) + [SECURITY_MAP['ChaCha20-Poly1305'], len(ct_chacha)])
		metrics, _ = benchmark("decrypt", size, chacha20_decryption, ct_chacha, tag_chacha, chacha_key, chacha_nonce)
		results_throughput.append(["ChaCha20 (AEAD)", "ChaCha20-Poly1305", "Decrypt", size] + list(metrics) + [SECURITY_MAP['ChaCha20-Poly1305'], len(ct_chacha)])

		# Asymmetric RSA Hybrid
		metrics, (enc_key_pkg, ct_rsa, tag_rsa) = benchmark("encrypt", size, rsa_hybrid_encryption, data, rsa_2048_pub)
		results_throughput.append(["RSA (Hybrid)", "RSA-2048", "Encrypt", size] + list(metrics) + [SECURITY_MAP['RSA-2048'], len(ct_rsa)])
		metrics, _ = benchmark("decrypt", size, rsa_hybrid_decryption, enc_key_pkg, ct_rsa, tag_rsa, rsa_2048_priv)
		results_throughput.append(["RSA (Hybrid)", "RSA-2048", "Decrypt", size] + list(metrics) + [SECURITY_MAP['RSA-2048'], len(ct_rsa)])

		# Asymmetric ECC Hybrid
		metrics, (ct_ecc, nonce_ecc, tag_ecc) = benchmark("encrypt", size, ecc_hybrid_encryption, data, ecc_384_pub_B, ecc_384_priv_A)
		results_throughput.append(["ECC (Hybrid)", "ECC-384", "Encrypt", size] + list(metrics) + [SECURITY_MAP['ECC-384'], len(ct_ecc)])
		metrics, _ = benchmark("decrypt", size, ecc_hybrid_decryption, ct_ecc, nonce_ecc, tag_ecc, ecc_384_pub_A, ecc_384_priv_B)
		results_throughput.append(["ECC (Hybrid)", "ECC-384", "Decrypt", size] + list(metrics) + [SECURITY_MAP['ECC-384'], len(ct_ecc)])

		# Signature Benchmarks
		metrics, rsa_sig = benchmark("sign", size, rsa_signing, data, rsa_2048_priv)
		results_throughput.append(["RSA (Signature)", "RSA-2048", "Sign", size] + list(metrics) + [SECURITY_MAP['RSA-2048'], len(rsa_sig)])
		metrics, _ = benchmark("verify", size, rsa_verification, data, rsa_sig, rsa_2048_pub)
		results_throughput.append(["RSA (Signature)", "RSA-2048", "Verify", size] + list(metrics) + [SECURITY_MAP['RSA-2048'], len(rsa_sig)])

		ecc_sig_priv_A = ec.generate_private_key(ec.SECP384R1())
		ecc_sig_pub_A = ecc_sig_priv_A.public_key()
		metrics, ecc_sig = benchmark("sign", size, ecc_signing, data, ecc_sig_priv_A)
		results_throughput.append(["ECC (Signature)", "ECC-384", "Sign", size] + list(metrics) + [SECURITY_MAP['ECC-384'], len(ecc_sig)])
		metrics, _ = benchmark("verify", size, ecc_verification, data, ecc_sig, ecc_sig_pub_A)
		results_throughput.append(["ECC (Signature)", "ECC-384", "Verify", size] + list(metrics) + [SECURITY_MAP['ECC-384'], len(ecc_sig)])


		# Kyber
		if KYBER_AVAILABLE:
			metrics, ct_kyber = benchmark("encrypt", size, kyber_encryption, data)
			results_throughput.append(["Kyber-PQCT", "Kyber-PQCT", "Encrypt", size] + list(metrics) + [SECURITY_MAP['Kyber'], len(ct_kyber)])
			metrics, dec_kyber= benchmark("decrypt", size, kyber_decryption, ct_kyber, kyber_priv)
			results_throughput.append(["Kyber-PQCT", "Kyber-PQCT", "Decrypt", size] + list(metrics) + [SECURITY_MAP['Kyber'], len(ct_kyber)])


	# Print the main table
	headers = ["Algorithm","Variant","Operation","Data Size (Bytes)","Mean Time (s)","Std Time (s)","Throughput (MB/s)","Memory (MB)","Security Level","Ciphertext Length"]
	print(tabulate(results_throughput, headers=headers, floatfmt=".8f"))

	# Save CSV results
	all_results = results_key_gen + results_throughput
	csv_headers = ["Algorithm","Variant","Operation","Data Size (Bytes)","Mean Time (s)","Std Time (s)","Throughput (MB/s)","Memory (MB)","Security Level","Ciphertext Length"]

	# Mapping key gen results to the full header list
	mapped_key_gen = [[r[0], r[0], r[1], 0, r[2], 0, 0, 0, r[3], "-"] for r in results_key_gen]

	with open("comparative_results.csv", "w", newline="") as f:
		writer = csv.writer(f)
		writer.writerow(csv_headers)
		writer.writerows(mapped_key_gen)
		writer.writerows(results_throughput)
	print(f"\nResults saved in comparative_results.csv")

if __name__ == '__main__':
	main()

