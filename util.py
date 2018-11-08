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
from pathlib import Path
from typing import List, Tuple
from datetime import date

from message import msg, error


def remove_suffix(base, suffix):
	if base.endswith(suffix):
		return base[:-len(suffix)]
	return base


def or_umask(mask: int) -> int:
	umask = os.umask(0o7777)
	os.umask(umask | mask)
	return umask


def read_file(file: Path) -> bytes:
	with open(file, 'rb') as file:
		return file.read()


def write_file(file: Path, data: bytes):
	with open(file, 'wb') as file:
		return file.write(data)


def file_path(type: str, name: str, date: date) -> Path:
	return Path(type) / name / '{}-{}.{}'.format(name, date.isoformat(), type)


def link_path(type: str, name: str) -> Path:
	return Path(type) / '{}.{}'.format(name, type)


def force_relative_symlink(src: Path, dest: Path):
	src = src.relative_to(dest.parent)
	if dest.is_symlink():
		try:
			os.unlink(dest)
		except: pass
	os.symlink(src, dest)


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
	serial += 1
	write_serial(file, serial)
	return serial
