#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Functions for generating random numbers."""

# borrowed from: https://github.com/sybrenstuvel/python-rsa


# Source inspired by code by Yesudeep Mangalapilly <yesudeep@gmail.com>

import os
import struct

def read_random_bits(nbits: int) -> bytes:
    """Reads 'nbits' random bits.

    If nbits isn't a whole number of bytes, an extra byte will be appended with
    only the lower bits set.
    """

    nbytes, rbits = divmod(nbits, 8)

    # Get the random bytes
    randomdata = os.urandom(nbytes)

    # Add the remaining random bits
    if rbits > 0:
        randomvalue = ord(os.urandom(1))
        randomvalue >>= (8 - rbits)
        randomdata = struct.pack("B", randomvalue) + randomdata

    return randomdata

def read_random_bytes(nbytes):
    return os.urandom(nbytes)

def read_random_int(nbits: int) -> int:
    """Reads a random integer of approximately nbits bits.
    """

    randomdata = read_random_bits(nbits)
    value = int.from_bytes(randomdata, 'big', signed=False)

    # Ensure that the number is large enough to just fill out the required
    # number of bits.
    value |= 1 << (nbits - 1)

    return value


def read_random_odd_int(nbits: int) -> int:
    """Reads a random odd integer of approximately nbits bits.

    >>> read_random_odd_int(512) & 1
    1
    """

    value = read_random_int(nbits)

    # Make sure it's odd
    return value | 1


