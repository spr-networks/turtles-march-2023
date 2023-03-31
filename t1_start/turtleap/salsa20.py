

"""
    A Python implementation of Salsa20.
    
    
    Copyright (c) 2009 by Larry Bugbee, Kent, WA
    ALL RIGHTS RESERVED.
    
    salsa20.py IS EXPERIMENTAL SOFTWARE FOR EDUCATIONAL
    PURPOSES ONLY.  IT IS MADE AVAILABLE "AS-IS" WITHOUT 
    WARRANTY OR GUARANTEE OF ANY KIND.  USE SIGNIFIES 
    ACCEPTANCE OF ALL RISK.  

    To make your learning and experimentation less cumbersome, 
    salsa20.py is free for any use.      
    
    This implementation is intended for Python 2.x.
    
    Larry Bugbee
    May 2009

    Reduced-Round modifications for 6.857 class made by Kevin King

"""

import struct
#-----------------------------------------------------------------------

class Salsa20(object):
    """
        Salsa20 was submitted to eSTREAM, an EU stream cipher
        competition).  Salsa20 was originally defined to be 20
        rounds.  Reduced round versions, Salsa20/8 (8 rounds) and
        Salsa20/12 (12 rounds), were also submitted.  Salsa20/12
        was chosen as one of the winners and 12 rounds was deemed
        the "right blend" of security and efficiency.  The default
        for this class is 20 rounds.

        Besides the encryption function and the decryption
        function being identical, exactly how Salsa20 works is
        very simple.  Salsa20 accepts a key and an iv to set up
        an initial 64-byte state.  For each 64-byte block of
        data, the state gets scrambled and XORed with the previous
        state.  This new state is then XORed with the input data
        to produce the output.  Salsa20's security is achieved via
        this one scrambling operation, repeated n times (rounds).

        Sample usage:

         s20 = Salsa20(key, iv, 12)
         ciphertext = s20.encrypt(message)


        Larry Bugbee
        May 2009
    """

    TAU    = ( 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 )
    SIGMA  = ( 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 )
    ROUNDS = 12                         # 8, 12, 20

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def __init__(self, key, iv=b'\x00'*8, rounds=ROUNDS):
        """ Both key and iv are bytestrings.  The key must be exactly
            16 or 32 bytes, 128 or 256 bits respectively.  The iv
            must be exactly 8 bytes (64 bits).

            Setting the key but relying on a default iv value (nulls)
            is dangerous.  Either provide the iv here or explicitly
            call iv_setup() to set the iv.

            Salsa20 exists in three basic versions defined by the
            number of rounds (8, 12, and 20).  20 rounds, Salsa20,
            is the default.  12 rounds, Salsa20/12, is the version
            selected by eSTREAM. The 8 round version, Salsa20/8 is
            faster and remains unbroken, but the lesser rounds
            reduces confidence.  Salsa20/8 should not be used with
            high value assets.
            
            The default number of rounds is 12.

        """
        self._key_setup(key)
        self.iv_setup(iv)
        self.ROUNDS = rounds

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _key_setup(self, key):
        """ key is converted to a list of 4-byte unsigned integers
            (32 bits).

            Calling this routine with a key value effectively resets
            the context/instance.  Be sure to set the iv as well.
        """
        if len(key) not in [16, 32]:
            raise Exception('key must be either 16 or 32 bytes')
        TAU   = self.TAU
        SIGMA = self.SIGMA
        key_state = [0]*16
        if len(key) == 16:
            k = list(struct.unpack('<4I', key))
            key_state[0]  = TAU[0]
            key_state[1]  = k[0]
            key_state[2]  = k[1]
            key_state[3]  = k[2]
            key_state[4]  = k[3]
            key_state[5]  = TAU[1]

            key_state[10] = TAU[2]
            key_state[11] = k[0]
            key_state[12] = k[1]
            key_state[13] = k[2]
            key_state[14] = k[3]
            key_state[15] = TAU[3]

        elif len(key) == 32:
            k = list(struct.unpack('<8I', key))
            key_state[0]  = SIGMA[0]
            key_state[1]  = k[0]
            key_state[2]  = k[1]
            key_state[3]  = k[2]
            key_state[4]  = k[3]
            key_state[5]  = SIGMA[1]

            key_state[10] = SIGMA[2]
            key_state[11] = k[4]
            key_state[12] = k[5]
            key_state[13] = k[6]
            key_state[14] = k[7]
            key_state[15] = SIGMA[3]
        self.key_state = key_state

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def iv_setup(self, iv):
        """ self.state and other working strucures are lists of
            4-byte unsigned integers (32 bits).

            The iv should never be reused with the same key value,
            but it is not a secret.  Use date, time or some other
            counter to be sure the iv is different each time, and
            be sure to communicate the IV to the receiving party.
            Prepending 8 bytes of iv to the ciphertext is the usual
            way to do this.

            Just as setting a new key value effectively resets the
            context, setting the iv also resets the context with
            the last key value entered.
        """
        if len(iv) != 8:
            raise Exception('iv must be 8 bytes')
        iv_state = self.key_state[:]
        v = list(struct.unpack('<2I', iv))
        iv_state[6] = v[0]
        iv_state[7] = v[1]
        iv_state[8] = 0
        iv_state[9] = 0
        self.state = iv_state
        self.lastchunk = 64     # flag to ensure all but the last
                                # chunks is a multiple of 64 bytes

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def encrypt(self, datain):
        """ datain and dataout are bytestrings.

            If the data is submitted to this routine in chunks,
            the chunk size MUST be an exact multiple of 64 bytes.
            Only the final chunk may be less than an even multiple.
        """
        if self.lastchunk != 64:
            raise Exception('size of last chunk not a multiple of 64 bytes')
        dataout = b''
        stream  = b''
        while datain:
            stream = self._salsa20_scramble();
            self.state[8] += 1
            if self.state[8] == 0:               # if overflow in state[8]
                self.state[9] += 1               # carry to state[9]
                # not to exceed 2^70 x 2^64 = 2^134 data size ??? <<<<
            dataout += self._xor(stream, datain[:64])
            if len(datain) <= 64:
                self.lastchunk = len(datain)
                return dataout
            datain = datain[64:]
        raise Exception('Huh?')
    decrypt = encrypt

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _ROL32(self, a,b):
        return ((a << b) | (a >> (32 - b))) & 0xffffffff

    def _salsa20_scramble(self):     # 64 bytes in
        """ self.state and other working strucures are lists of
            4-byte unsigned integers (32 bits).

            output must be converted to bytestring before return.
        """
        x = self.state[:]    # makes a copy
        for i in range(self.ROUNDS):
            if i % 2 == 0:
                x[ 4] ^= self._ROL32( (x[ 0]+x[12]) & 0xffffffff,  7)
                x[ 8] ^= self._ROL32( (x[ 4]+x[ 0]) & 0xffffffff,  9)
                x[12] ^= self._ROL32( (x[ 8]+x[ 4]) & 0xffffffff, 13)
                x[ 0] ^= self._ROL32( (x[12]+x[ 8]) & 0xffffffff, 18)
                x[ 9] ^= self._ROL32( (x[ 5]+x[ 1]) & 0xffffffff,  7)
                x[13] ^= self._ROL32( (x[ 9]+x[ 5]) & 0xffffffff,  9)
                x[ 1] ^= self._ROL32( (x[13]+x[ 9]) & 0xffffffff, 13)
                x[ 5] ^= self._ROL32( (x[ 1]+x[13]) & 0xffffffff, 18)
                x[14] ^= self._ROL32( (x[10]+x[ 6]) & 0xffffffff,  7)
                x[ 2] ^= self._ROL32( (x[14]+x[10]) & 0xffffffff,  9)
                x[ 6] ^= self._ROL32( (x[ 2]+x[14]) & 0xffffffff, 13)
                x[10] ^= self._ROL32( (x[ 6]+x[ 2]) & 0xffffffff, 18)
                x[ 3] ^= self._ROL32( (x[15]+x[11]) & 0xffffffff,  7)
                x[ 7] ^= self._ROL32( (x[ 3]+x[15]) & 0xffffffff,  9)
                x[11] ^= self._ROL32( (x[ 7]+x[ 3]) & 0xffffffff, 13)
                x[15] ^= self._ROL32( (x[11]+x[ 7]) & 0xffffffff, 18)
            if i % 2 == 1:
                x[ 1] ^= self._ROL32( (x[ 0]+x[ 3]) & 0xffffffff,  7)
                x[ 2] ^= self._ROL32( (x[ 1]+x[ 0]) & 0xffffffff,  9)
                x[ 3] ^= self._ROL32( (x[ 2]+x[ 1]) & 0xffffffff, 13)
                x[ 0] ^= self._ROL32( (x[ 3]+x[ 2]) & 0xffffffff, 18)
                x[ 6] ^= self._ROL32( (x[ 5]+x[ 4]) & 0xffffffff,  7)
                x[ 7] ^= self._ROL32( (x[ 6]+x[ 5]) & 0xffffffff,  9)
                x[ 4] ^= self._ROL32( (x[ 7]+x[ 6]) & 0xffffffff, 13)
                x[ 5] ^= self._ROL32( (x[ 4]+x[ 7]) & 0xffffffff, 18)
                x[11] ^= self._ROL32( (x[10]+x[ 9]) & 0xffffffff,  7)
                x[ 8] ^= self._ROL32( (x[11]+x[10]) & 0xffffffff,  9)
                x[ 9] ^= self._ROL32( (x[ 8]+x[11]) & 0xffffffff, 13)
                x[10] ^= self._ROL32( (x[ 9]+x[ 8]) & 0xffffffff, 18)
                x[12] ^= self._ROL32( (x[15]+x[14]) & 0xffffffff,  7)
                x[13] ^= self._ROL32( (x[12]+x[15]) & 0xffffffff,  9)
                x[14] ^= self._ROL32( (x[13]+x[12]) & 0xffffffff, 13)
                x[15] ^= self._ROL32( (x[14]+x[13]) & 0xffffffff, 18)
        # OMIT FINAL XOR of initial round state
        # for i in xrange(16):
            # x[i] = (x[i] + self.state[i]) & 0xffffffff
        output = struct.pack('<16I',
                            x[ 0], x[ 1], x[ 2], x[ 3],
                            x[ 4], x[ 5], x[ 6], x[ 7],
                            x[ 8], x[ 9], x[10], x[11],
                            x[12], x[13], x[14], x[15])
        return output                          # 64 bytes out
   
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _xor(self, stream, din):
        dout = []
        for i in range(len(din)):
            dout.append(stream[i]^din[i])
        return bytes(dout)

