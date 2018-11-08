# Copyright 2017-2019 Fizyr B.V. - https://fizyr.com
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, List, Tuple, Optional, Generator

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import util

crypto_backend = default_backend()


def name_key_to_oid(key: str) -> Optional[NameOID]:
	key = key.upper()
	if key == 'C':
		return NameOID.COUNTRY_NAME
	elif key == 'ST':
		return NameOID.STATE_OR_PROVINCE_NAME
	elif key == 'L':
		return NameOID.LOCALITY_NAME
	elif key == 'DC':
		return NameOID.DOMAIN_COMPONENT
	elif key == 'O':
		return NameOID.ORGANIZATION_NAME
	elif key == 'OU':
		return NameOID.ORGANIZATIONAL_UNIT_NAME
	elif key == 'CN':
		return NameOID.COMMON_NAME
	else:
		return None


def name_oid_to_key(oid: NameOID) -> Optional[str]:
	if oid == NameOID.COUNTRY_NAME:
		return 'C'
	elif oid == NameOID.STATE_OR_PROVINCE_NAME:
		return 'ST'
	elif oid == NameOID.LOCALITY_NAME:
		return 'L'
	elif oid == NameOID.DOMAIN_COMPONENT:
		return 'DC'
	elif oid == NameOID.ORGANIZATION_NAME:
		return 'O'
	elif oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
		return 'OU'
	elif oid == NameOID.COMMON_NAME:
		return 'CN'
	else:
		return None


def parse_name_attribute(string: str) -> x509.NameAttribute:
	string = string.strip()
	key, sep, value = string.partition('=')
	if key:
		key = key.strip()
	if value:
		value = value.strip()
	if not key or not sep or not value:
		raise ValueError('invalid RDN syntax: should be key=value, got {}'.format(rdn))

	oid = name_key_to_oid(key)
	if not oid:
		raise ValueError('failed to parse RND: unknown component: {}'.format(key))

	return x509.NameAttribute(oid, value)


def parse_dn(value: str) -> x509.Name:
	return x509.Name(map(lambda x: x509.RelativeDistinguishedName([parse_name_attribute(x)]), value.split(',')))


def format_attribute(attrib: x509.NameAttribute):
	key = name_oid_to_key(attrib.oid)
	if not key:
		raise ValueError('unknown name attribute: {}'.format(attrib))
	return '{}={}'.format(key, attrib.value)


def format_rdn(rdn: x509.RelativeDistinguishedName):
	rdn = list(rdn)
	if len(rdn) == 1:
		return format_attribute(rdn[0])

	return '{{{}}}'.format(', '.join(map(format_attribute, rdn)))


def format_name(name: x509.Name) -> str:
	return ', '.join(map(format_rdn, name.rdns))


def generate_serial() -> int:
	return int.from_bytes(os.urandom(20), byteorder='little') % (1 << 59)


def get_subject_alt_names(object) -> List[x509.GeneralName]:
	try:
		extension = object.extensions.get_extension_for_class(x509.SubjectAlternativeName)
	except x509.ExtensionNotFound:
		return []
	return list(extension.value)


def get_basic_ca_constraint(object) -> Optional[bool]:
	try:
		extension = object.extensions.get_extension_for_class(x509.BasicConstraints)
	except x509.ExtensionNotFound:
		return None
	return extension.value.ca


def get_dns_names(names: List[x509.GeneralName]) -> List[x509.DNSName]:
	return list(filter(lambda x: isinstance(x, x509.DNSName), names))


def get_first_dns_name(names: List[x509.GeneralName]) -> Optional[x509.DNSName]:
	try:
		return get_dns_names(names)[0]
	except IndexError:
		return None


def read_serial(file: Path) -> int:
	with open(file, 'r') as file:
		return int(file.read(), 16)


def write_serial(file: Path, value: int):
	with open(file, 'w') as file:
		file.write(hex(value))


def bump_serial(file: Path) -> int:
	try:
		serial = read_serial(file)
	except FileNotFoundError:
		serial = generate_serial()
	serial = (serial + 1) % (1 << 59)
	write_serial(file, serial)
	return serial

def ca_extensions(dns_name: str, max_path_length: Optional[int]) -> List[Tuple[x509.Extension, bool]]:
	return [
		(x509.BasicConstraints(True, max_path_length), True),
		(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True),
		(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), True),
		(x509.NameConstraints([x509.DNSName('.' + dns_name)], []), True),
	]


def client_extensions(dns_name: str) -> List[Tuple[x509.Extension, bool]]:
	return [
		(x509.BasicConstraints(False, None), True),
		(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True),
		(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), True),
		(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), True),
	]


def add_extensions(object, extensions: Iterable[Tuple[x509.Extension, bool]]):
	for extension, critical in extensions:
		object = object.add_extension(extension, critical)
	return object;


def replace_name_attribute(name: x509.Name, oid: NameOID, new_value: str) -> x509.Name:
	new_attribs = []
	replaced    = False
	for attrib in original:
		if not replaced and attrib.oid == oid:
			new_attribs.append(x509.NameAttribute(oid, new_value))
			replaced = True
		else:
			new_attribs.append(attrib)
			break
	return x509.Name(new_attribs)

def prefix_name(name: x509.Name, oid: NameOID, value: str) -> x509.Name:
	new_rdn = x509.RelativeDistinguishedName([x509.NameAttribute(oid, value)])
	return x509.Name([new_rdn] + name.rdns)

def replace_common_name(name: x509, new_value: str) -> x509.Name:
	replace_name_attribute(name, NameOID.COMMON_NAME, new_value)


def generate_rsa_key(file: Path, bits: int = 4096) -> rsa.RSAPrivateKey:
	umask = util.or_umask(0o277)

	key = rsa.generate_private_key(public_exponent = 65537, key_size = bits, backend = crypto_backend)

	util.write_file(file, key.private_bytes(
		encoding = serialization.Encoding.PEM,
		format = serialization.PrivateFormat.PKCS8,
		encryption_algorithm = serialization.NoEncryption(),
	))

	os.umask(umask)

	return key


def load_key(file: Path):
	with open(file, 'rb') as file:
		return serialization.load_pem_private_key(file.read(), password=None, backend=crypto_backend)


def make_csr(file: Path, key: rsa.RSAPrivateKey, name: x509.Name, extensions: List[Tuple[x509.Extension, bool]]) -> x509.CertificateSigningRequest:
	csr = x509.CertificateSigningRequestBuilder()
	csr = csr.subject_name(name)
	for extension, critical in extensions:
		csr = csr.add_extension(extension, critical)
	csr = csr.sign(key, hashes.SHA512(), crypto_backend)
	util.write_file(file, csr.public_bytes(serialization.Encoding.PEM))

	return csr


def load_csr(file: Path) -> x509.CertificateSigningRequest:
	return x509.load_pem_x509_csr(util.read_file(file), crypto_backend)


def sign_csr(
	file       : Path,
	chain      : bytes,
	csr        : x509.CertificateSigningRequest,
	ca_key     : rsa.RSAPrivateKey,
	ca_cert    : x509.Certificate,
	name       : x509.Name,
	serial     : int,
	extensions : List[Tuple[x509.Extension, bool]],
	days       : int,
	now        : datetime,
) -> x509.Certificate:
	cert = x509.CertificateBuilder()
	cert = cert.issuer_name(ca_cert.subject)
	cert = cert.subject_name(name)
	cert = cert.serial_number(serial)
	cert = cert.public_key(csr.public_key())
	cert = cert.not_valid_before(now)
	cert = cert.not_valid_after(now + timedelta(days=days))
	for extension, critical in extensions:
		cert = cert.add_extension(extension, critical)

	cert = cert.sign(ca_key, hashes.SHA512(), crypto_backend)

	with open(file, 'wb') as file:
		file.write(cert.public_bytes(serialization.Encoding.PEM))
		file.write(chain)

	return cert


def make_self_signed_cert(
	file       : Path,
	key        : rsa.RSAPrivateKey,
	name       : x509.Name,
	serial     : int,
	extensions : List[Tuple[x509.Extension, bool]],
	days       : int,
	now        : datetime,
) -> x509.Certificate:
	cert = x509.CertificateBuilder()
	cert = cert.issuer_name(name)
	cert = cert.subject_name(name)
	cert = cert.serial_number(serial)
	cert = cert.public_key(key.public_key())
	cert = cert.not_valid_before(now)
	cert = cert.not_valid_after(now + timedelta(days=days))
	for extension, critical in extensions:
		cert = cert.add_extension(extension, critical)

	cert = cert.sign(key, hashes.SHA512(), crypto_backend)

	util.write_file(file, cert.public_bytes(serialization.Encoding.PEM))
	return cert


def load_certificate(file: Path) -> x509.Certificate:
	return x509.load_pem_x509_certificate(util.read_file(file), crypto_backend)


class PemBlob:
	def __init__(self, name: str, data: bytes):
		self.name = name
		self.data = data


PEM_BEGIN_PREFIX = b'-----BEGIN '
PEM_END_PREFIX   = b'-----END '
PEM_SUFFIX       = b'-----\n'

def read_pem_blobs(data: bytes) -> Generator[PemBlob, None, None]:
	current = None
	body    = b''
	for line in data.splitlines(keepends=True):
		if current is None and line.startswith(PEM_BEGIN_PREFIX) and line.endswith(PEM_SUFFIX):
			current = line[len(PEM_BEGIN_PREFIX):-len(PEM_SUFFIX)]
			body    = line
		elif current is not None:
			body += line
			if line == PEM_END_PREFIX + current + PEM_SUFFIX:
				yield PemBlob(current.decode('utf8'), body)
				current = None


def read_first_pem_blob(data: bytes, name: str) -> Optional[bytes]:
	for blob in read_pem_blobs(data):
		if blob.name == name:
			return blob.data
	return None


def read_last_pem_blob(data: bytes, name: str) -> Optional[bytes]:
	result = None
	for blob in read_pem_blobs(data):
		if blob.name == name:
			result = blob
	return result.data


def load_first_certificate(data: bytes) -> Optional[x509.Certificate]:
	blob = read_first_pem_blob(data, 'CERTIFICATE')
	if not blob:
		return None
	return x509.load_pem_x509_certificate(blob, crypto_backend)
