#!/usr/bin/env python
import binascii

# example:
key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
plaintext = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
ciphertext = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0xb, 0x32]

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

Rcon = (
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
    0x80000000, 0x1B000000, 0x36000000, 0x6C000000, 0xD8000000, 0xAB000000, 0x4D000000, 0x9A000000,
    0x2F000000, 0x5E000000, 0xBC000000, 0x63000000, 0xC6000000, 0x97000000, 0x35000000, 0x6A000000,
    0xD4000000, 0xB3000000, 0x7D000000, 0xFA000000, 0xEF000000, 0xC5000000, 0x91000000, 0x39000000,
)


InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

def ToMatrix(text):
    temp = []
    for i in range(16):
        if i / 4 == 0:
            temp.append([text[i]])
        else:
            temp[i % 4].append(text[i])
    return temp

def ToText(matrix):
    temp = []
    for i in range(4):
        for j in range(4):
            temp.append(matrix[j][i])
    return temp

def ListToHex(List):
    temp = "0x"
    for i in List:
        if len(hex(i)[2:]) < 2:
            temp += "0"+hex(i)[2:]
        else:
            temp += hex(i)[2:]
    return temp

def HexToList(Hex):
    temp = []
    for i in range(2,len(Hex)):
        if i % 2 == 0:
            temp.append(eval("0x"+Hex[i:i+2]))
    return temp

def aTob(matrix):
    temp = [[],[],[],[]]
    for i in range(4):
        for j in range(4):
            temp[i].append(matrix[j][i])
    return temp

def PrintHex(matrix):
    temp = [[],[],[],[]]
    for i in range(4):
        for j in range(4):
            temp[i].append(hex(matrix[i][j]))
    print temp

class AES:
    def __init__(self, key):
        self.Nk = 4
        self.Nb = 4
        self.Nr = 10
        self.round_key = ToMatrix(key)
        self.K = self.ExpandKey(ToText(self.round_key))

    def Encrypt(self, plaintext):
        print 'Encrypting.....\n\n'

        self.plain_text = ToMatrix(plaintext)
        self.plain_text = self._add_round_key(self.plain_text,self.round_key)

        K = self.K

        print '[+]0th Round.'
        print 'Start of Round: '
        PrintHex(ToMatrix(plaintext))
        print 'Round Key Value: '
        PrintHex(self.round_key)

        for i in range(1,10):
            print '\n' + '*' * 20
            print '[+]%dth Round.' % i
            self.plain_text = self._round_encrypt(self.plain_text, aTob(K[4 * i : 4 * (i + 1)]))
            print 'Round Key Value: '
            PrintHex(aTob(K[4 * i : 4 * (i + 1)]))

        print '\n' + '*' * 20
        self.plain_text = self.SubBytes(self.plain_text)
        self.plain_text = self.ShifrRows(self.plain_text)
        ciphertext = self._add_round_key(self.plain_text, aTob(K[40:]))

        print "\nResult: \n"
        PrintHex(ciphertext)
        return ciphertext

    def Decrypt(self, ciphertext):
        print 'Decrypting.....\n\n'

        K = self.K
        self.cipher_text = ToMatrix(ciphertext)
        self.cipher_text = self._add_round_key(self.cipher_text, aTob(K[40:]))
        self.cipher_text = self.Inv_SubBytes(self.Inv_ShifrRows(self.cipher_text))

        print '[+]0th Round.'
        print 'Start of Round: '
        PrintHex(ToMatrix(ciphertext))
        print 'Round Key Value: '
        PrintHex(aTob(K[40:]))

        for i in range(9, 0, -1):
            print '\n' + '*' * 20
            print '[+]%dth Round.' % (10-i)
            self.cipher_text = self._round_decrypt(self.cipher_text, aTob(K[4 * i : 4 * (i + 1)]))
            print 'Round Key Value: '
            PrintHex(aTob(K[4 * i : 4 * (i + 1)]))

        print '\n' + '*' * 20
        plaintext = self._add_round_key(self.cipher_text, aTob(K[:4]))

        print "\nResult: \n"
        PrintHex(plaintext)
        return plaintext

    def ExpandKey(self, key):
        K = [[] for val in range(self.Nb * (self.Nr + 1))]

        for i in range(self.Nk):
            K[i] = [key[4*i], key[(4*i)+1], key[(4*i)+2], key[(4*i)+3]]
        for i in range(self.Nk, (self.Nr + 1) * self.Nb):
            if i % 4 == 0:
                temp = self._subWord(self._Rot(K[i-1]))
                temp = ListToHex(temp)
                temp = eval(temp) ^ Rcon[i/self.Nk]
                temp = temp ^ eval(ListToHex(K[i-self.Nk]))
                K[i] = HexToList(hex(temp))
            else:
                for j in range(4):
                    byte = K[i-4][j] ^ K[i-1][j]
                    K[i].append(byte)
        return K

    def SubBytes(self, s):
        print "Start of Round: "
        PrintHex(s)
        for i in range(4):
            for j in range(4):
                s[i][j] = Sbox[s[i][j]]
        print "After SubBytes: "
        PrintHex(s)
        return s

    def Inv_SubBytes(self, s):
        print "Start of Round: "
        PrintHex(s)
        for i in range(4):
            for j in range(4):
                s[i][j] = InvSbox[s[i][j]]
        print "After SubBytes: "
        PrintHex(s)
        return s

    def ShifrRows(self, s):
        temp = [[],[],[],[]]
        for i in range(4):
            for j in range(4):
                if j + i >= 4:
                    temp[i].append(s[i][j+i-4])
                else:
                    temp[i].append(s[i][j+i])
        print "After ShiftRows: "
        PrintHex(temp)
        return temp

    def Inv_ShifrRows(self, s):
        temp = [[],[],[],[]]
        for i in range(4):
            for j in range(4):
                if j - i >= 4:
                    temp[i].append(s[i][j-i+4])
                else:
                    temp[i].append(s[i][j-i])
        print "After ShiftRows: "
        PrintHex(temp)
        return temp

    def MixColumns(self,s):
        result = [[],[],[],[]]
        #[[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
        Mixmatrix = ToMatrix([2, 1, 1, 3, 3, 2, 1, 1, 1, 3, 2, 1, 1, 1, 3, 2])

        #matrix ^ matrix
        s = ToText(s)
        for i in range(4):
            for j in range(4):
                temp = 0b00000000
                for k in range(4):
                    temp ^= self._mult(Mixmatrix[i][k],s[j*4+k])
                result[i].append(temp)
        print "After MixColumns: "
        PrintHex(result)
        return result

    def Inv_MixColumns(self,s):
        result = [[],[],[],[]]
        Mixmatrix = ToMatrix([14, 9, 13, 11, 11, 14, 9, 13, 13, 11, 14, 9, 9, 13, 11, 14])

        #matrix ^ matrix
        s = ToText(s)
        for i in range(4):
            for j in range(4):
                temp = 0b00000000
                for k in range(4):
                    temp ^= self._mult(Mixmatrix[i][k],s[j*4+k])
                result[i].append(temp)
        print "After MixColumns: "
        PrintHex(result)
        return result

    def _Rot(self,s):
        temp = []
        for k in range(4):
            if k+1 >= 4:
                temp.append(s[k-3])
            else:
                temp.append(s[k+1])
        return temp

    def _subWord(self,word):
        for i, byte in enumerate(word):
            word[i] = Sbox[byte]
        return word

    def _add_round_key(self,s,k):
        for i in range(4):
            for j in range(4):
                s[i][j] ^= k[i][j]
        return s

    def _round_encrypt(self, s, k):
        s = self.SubBytes(s)
        s = self.ShifrRows(s)
        s = self.MixColumns(s)
        return self._add_round_key(s, k)

    def _round_decrypt(self, s, k):
        s = self._add_round_key(s, k)
        s = self.Inv_MixColumns(s)
        s = self.Inv_ShifrRows(s)
        s = self.Inv_SubBytes(s)
        return s

    def _mult(self, byte1, byte2): # returns a(x)b(x) (a byte)
        sum = 0b00000000
        toBeXored = byte2
        for i in range(8):
            if (byte1 & 0b00000001) == 0b00000001:
                sum = sum ^ toBeXored

            toBeXored = self._xtime(toBeXored)
            byte1 = byte1 >> 1

        return sum

    def _xtime(self, byte): # returns a byte
        shiftedB = byte << 1
        if (shiftedB & 0b100000000) == 0b100000000:
            shiftedB = shiftedB ^ 0b100011011;

        return shiftedB

def InputHex(str_):
    return HexToList('0x'+binascii.b2a_hex(str_))

# action = raw_input('Action Encrypt/Decrypt(E/D):')

# str_ = raw_input('Input key:')
# key = InputHex(str_)

test = AES(key)

# if action == 'E' or action == 'e':
#     str_ = raw_input('Input plaintext:')
#     plaintext = InputHex(str_)
#     result = test.Encrypt(plaintext)
#     print ListToHex(ToText(result))
# else:
#     str_ = raw_input('Input ciphertext:')
#     ciphertext = HexToList(str_)
#     result = test.Decrypt(ciphertext)
#     for i in ToText(result):
#         print chr(i),

print ToText(test.Encrypt(plaintext))
print ToText(test.Decrypt(ciphertext))
