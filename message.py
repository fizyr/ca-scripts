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


import sys

termcolors = dict(
	reset      = '\x1b[0m',
	bold       = '\x1b[1m',
	red        = '\x1b[31m',
	green      = '\x1b[32m',
	yellow     = '\x1b[33m',
	blue       = '\x1b[34m',
	magenta    = '\x1b[35m',
	cyan       = '\x1b[36m',
	white      = '\x1b[37m',
	bg_red     = '\x1b[41m',
	bg_green   = '\x1b[42m',
	bg_yellow  = '\x1b[43m',
	bg_blue    = '\x1b[44m',
	bg_magenta = '\x1b[45m',
	bg_cyan    = '\x1b[46m',
	bg_white   = '\x1b[47m',
)

def write(prefix, message):
	sys.stderr.write(prefix)
	sys.stderr.write(message)
	sys.stderr.write(termcolors['reset'])
	sys.stderr.write('\n')

def plain(format, *args, **kwargs):
	write(
		'{bold}    '.format(**termcolors),
		format.format(*args, **termcolors, **kwargs)
	)

def msg(format, *args, **kwargs):
	write(
		'{bold}{green}==>{reset} {bold}'.format(**termcolors),
		format.format(*args, **termcolors, **kwargs)
	)

def msg2(format, *args, **kwargs):
	write(
		'{blue}  ->{reset} {bold}'.format(**termcolors),
		format.format(*args, **termcolors, **kwargs)
	)

def warning(format, *args, **kwargs):
	write(
		'{bold}{yellow}==> WARNING:{reset} {bold}'.format(**termcolors),
		format.format(*args, **termcolors, **kwargs)
	)

def error(format, *args, **kwargs):
	write(
		'{bold}{red}==> ERROR:{reset} {bold}'.format(**termcolors),
		format.format(*args, **termcolors, **kwargs)
	)
