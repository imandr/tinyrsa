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

# borrowed from: https://github.com/sybrenstuvel/python-rsa

import math, random
from tinyrsa.rnd import read_random_odd_int

def miller_rabin_primality_testing(n):
    """Calculates whether n is composite (which is always correct) or prime
    (which theoretically is incorrect with error probability 4**-k), by
    applying Miller-Rabin primality testing.

    For reference and implementation example, see:
    https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

    :param n: Integer to be tested for primality.
    :type n: int
    :param k: Number of rounds (witnesses) of Miller-Rabin testing.
    :type k: int
    :return: False if the number is composite, True if it's probably prime.
    :rtype: bool
    """

    bitsize = n.bit_length()
    # Set number of rounds.
    if bitsize >= 1536:
        k = 3
    elif bitsize >= 1024:
        k = 4
    elif bitsize >= 512:
        k = 7
    else:
        # For smaller bitsizes, set arbitrary number of rounds.
        k = 10

    
    # prevent potential infinite loop when d = 0
    if n < 2:
        return False

    # Decompose (n - 1) to write it as (2 ** r) * d
    # While d is even, divide it by 2 and increase the exponent.
    d = n - 1
    r = 0

    while not (d & 1):
        r += 1
        d >>= 1

    # Test k witnesses.
    for _ in range(k):
        # Generate random integer a, where 2 <= a <= (n - 2)
        a = random.randint(2, n - 2)

        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == 1:
                # n is composite.
                return False
            if x == n - 1:
                # Exit inner loop and continue with next witness.
                break
        else:
            # If loop doesn't break, n is composite.
            return False

    return True

primes_100 = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 
              89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 
              179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 
              271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 
              379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 
              479, 487, 491, 499, 503, 509, 521, 523, 541
             ]
primes_100_set = set(primes_100)
last_prime_100 = max(primes_100)

def is_prime(x):
    if x < 2: return False
    if x == 2: return True
    if x & 1 == 0: return False
    if x in primes_100_set: return True
    for p in primes_100:
        if x % p == 0:
            return False
    if x <= last_prime_100**2:
        return True
    return miller_rabin_primality_testing(x)
    
def get_prime(nbits):
    x = read_random_odd_int(nbits)
    while not is_prime(x):
        x = read_random_odd_int(nbits)
    return x

def extended_gcd(a, b):
    """Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb
    """
    # r = gcd(a,b) i = multiplicitive inverse of a mod b
    #      or      j = multiplicitive inverse of b mod a
    # Neg return values for i or j are made positive mod b or a respectively
    # Iterateive Version is faster and uses much less stack space
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  # Remember original a/b to remove
    ob = b  # negative values from return results
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  # If neg wrap modulo orignal b
    if ly < 0:
        ly += oa  # If neg wrap modulo orignal a
    return a, lx, ly  # Return only positive values


def gcd(p, q):
    if q > p:
        p, q = q, p
    while q != 0:
        (p, q) = (q, p % q)
    return p

def generate_p_q(length, e):
    nbits = length//2
    pbits = nbits + nbits//16
    qbits = nbits - nbits//16
    
    done = False
    #print("bits:", pbits, qbits)
    change_p = True
    p = 0
    q = get_prime(qbits)
    while not done:
        if change_p:
            p = get_prime(pbits)
        else:
            q = get_prime(qbits)
        change_p = not change_p
            
        #print("canditates:", p, q)
        if (p*q).bit_length() != length:
            #print("wrong length", (p*q).bit_length())
            continue
        if p <= q: continue
            
        L = (p-1)*(q-1)
        
        if gcd(L, e) != 1:
            #print("L not coprime with e")
            continue
        
        return p, q

