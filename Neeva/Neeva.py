# coding: utf-8
"""
The program is the implementation of Neeva-Hash algorithm
which is from the paper "Neeva: A Lightweight Hash Function"
@edition: python2.7
@author: Cathon
@date: 2016.09.11
"""


class NeevaHash:
    __s_box = {'0': 'c',
               '1': '5',
               '2': '6',
               '3': 'b',
               '4': '9',
               '5': '0',
               '6': 'a',
               '7': 'd',
               '8': '3',
               '9': 'e',
               'a': 'f',
               'b': '8',
               'c': '4',
               'd': '7',
               'e': '1',
               'f': '2'}

    __hex_bin_map = {'0': '0000',
                     '1': '0001',
                     '2': '0010',
                     '3': '0011',
                     '4': '0100',
                     '5': '0101',
                     '6': '0110',
                     '7': '0111',
                     '8': '1000',
                     '9': '1001',
                     'a': '1010',
                     'b': '1011',
                     'c': '1100',
                     'd': '1101',
                     'e': '1110',
                     'f': '1111'}

    __bin_hex_map = {'0000': '0',
                     '0001': '1',
                     '0010': '2',
                     '0011': '3',
                     '0100': '4',
                     '0101': '5',
                     '0110': '6',
                     '0111': '7',
                     '1000': '8',
                     '1001': '9',
                     '1010': 'a',
                     '1011': 'b',
                     '1100': 'c',
                     '1101': 'd',
                     '1110': 'e',
                     '1111': 'f'}

    __RC = {0: 'c7b119402be75b5fe34230e1c6de7511503b802a96a7f546fd02a80d8cb27863',
            1: '6990c02e24cf9ab94c057e4e08726162dccb97ca280e1ccb6db961615a126f97',
            2: 'ff223911f7f604c272d7ec72db58b760669de33dee6be0202550c439d270f05e',
            3: 'f5a6c2820cac1ab3b263f3f68b1d3c53118bb9d52521bd520eb7a1e5a3cb9e5b',
            4: '1612115e8201b0311ea4d23d2bb3f906832a60191b4181d9f3f2a22b9671f3ba',
            5: 'd299ae33da1d4ed5ed9c5c77047b758fe01bb24d4801a33b8050013fbb396b14',
            6: '1d18fe11cd6aa678cfe053451418e7dbb8b382220290ebd42291a6ff6c4c1743',
            7: '4afc5e1277a7355ec0b5a2231a9e2ccc02f555d4739836567bcdef91d914cfe2',
            8: 'ece8b0d3361a8b569fe8cecb31b9ecd7e730d51ab9f94b620357d728fdbeda72',
            9: '1e5d2b7bfca2f0cce303b2bf33be3dc4ce60882398bb64f60b7adb092bface29',
            10: '89a2a6a2baf87b8705ead75447d16334479ad1f87a467e1245e036f2119df0eb',
            11: '96b970981eb889eb988a96bf01fc1dd13a0c119519ffe34590a0fe36c225749e',
            12: '10f20d64be3da2783114fe4dfaef826db18e6e25cf42ff6f22a604a3496878d6',
            13: '104d1cdde66f47312729c321e0ca3b99d39b754672e3910d6a4ddc204a7989f6',
            14: '3b346ce05703de7eb2719130af1b426660aac3243e43b2234b95c10d28d13528',
            15: '786d780921f9490b94476162609fd9e100c2fdb347fe2208086b1d8fc2459661',
            16: '888460b5299cee14e2095e0676c4ee73aef17819767cd8ee9223162928c83763',
            17: 'e80f465c9f7cfc78a49539b737812cbcdcd37347cf4d4025ac70a24356ef05d3',
            18: 'ce366bd878a9218786f4fddef33e2ad51012edbde19085f0ebcee84638fa7126',
            19: '76a45e9feb2c4123370448278054b494b62d481b5c8403a1cab5529bea62b745',
            20: 'adf6d3e93166a6f892b0a9d59d55a1a51ca11b9cb530d7f5d50946dd9ceeda2c',
            21: '3246b10c987b174fd9f598444a5c42e9ea390cf5c4c5a5fdba7e0a08f59d2f10',
            22: '9f3903e5338b6415d92b4707462d4ef82844f7897dcf8f702e131c062682a99a',
            23: '70ff29c4c11f18008dd533acd7248c9b0a642ebaf42b4fb20898288b394e5f33',
            24: 'cb8befdfdf5b238b1c730c0bf30855bbc7a0bfa5ae3516ab7edd326f5611ae48',
            25: 'dfeb28672f6bcfc1afb3d11a97bbe65fc0ffb97d526913fca74d7e995ba9a3a6',
            26: '9f7f4896467352c824c941af49866c11246f4529d55c0b1110b9047575249533',
            27: '79990702621c531145378996444dc267629c221a9d6fc3d75be71d704ae1bac2',
            28: '5f6731bf692923f1b6d1dce74905c7ca504acba3d0b95bc79d7787025783e5cf',
            29: 'ec1d0d8ddd6b5d8dcf1c5a759fae7dc0c206489bc8f14d8d9e4a6bcb2287c7c3',
            30: 'fc2d8fd04b8f582fadd6205ca979b648a2c6fc9b00ca8b389cd94a3ef90ad435',
            31: '40e308b38501c4273130a587906a0ccc5461f947f201759b50b61dd32adedb9a'}

    __t = 0       # number of message blocks
    __cv = []
    __debug = False
    __plainhex = ''

    def __init__(self, hexstr='', __debug='False'):
        self.__plainhex = hexstr
        self.__debug = __debug
        self.__cv.insert(0, '0' * 256)

    def hexstr2binary(self, hexstr):
        return ''.join((self.__hex_bin_map[c] for c in hexstr))

    def binary2hexstr(self, binary):
        """
        :param binary: the binary string should be a multiple of 8 bit
        """
        s = ''
        for i in range(len(binary)/4):
            s += self.__bin_hex_map[binary[4*i:4*i+4]]
        return s

    @staticmethod
    def xor(bins1, bins2):
        max_len = max(len(bins1), len(bins2))
        if len(bins1) < max_len:
            bins1 += '0' * (max_len - len(bins1))
        elif len(bins2) < max_len:
            bins2 += '0' * (max_len - len(bins2))
        s = ''
        for i in range(max_len):
            if bins1[i] == bins2[i]:
                s += '0'
            else:
                s += '1'
        return s

    def S(self, binstr):
        """
        :param binstr: the binary string is applied with Present S-box
        """
        s = ''
        for i in range(int(len(binstr)/4)):
            piece = binstr[4*i:4*i+4]
            char = self.__bin_hex_map[piece]
            new_char = self.__s_box[char]
            new_piece = self.__hex_bin_map[new_char]
            s += new_piece
        return s

    def F(self, binstr):
        """
        Feistel structure
        :param binstr: the binary string is applied with XOR operator
        """
        s = ''
        for i in range(4):
            for j in range(3):
                s += self.xor(binstr[16*(4*i+j):16*(4*i+j)+16], binstr[16*(4*i+3):16*(4*i+4)])
            s += binstr[16*(4*i+3):16*(4*i+4)]
        return s

    @staticmethod
    def rotl8(binstr):
        return binstr[8:] + binstr[:8]

    @staticmethod
    def add(bins1, bins2):
        """
        add two 16-bit binary string, mod 2**16
        :param bins1: one 16-bit binary string to add
        :param bins2: another 16-bit binary string to add
        """
        s = ''
        j = 0
        for i in range(16):
            j += int(bins1[-i-1]) + int(bins2[-i-1])
            s += str(j % 2)
            j /= 2
        return s[::-1]

    def f(self, binstr):
        new = ''
        for j in range(32):
            Bi = self.S(binstr)
            Bi = self.F(Bi)
            Bi = self.rotl8(Bi)
            RC_bin = self.hexstr2binary(self.__RC[j])
            new = ''
            for i in range(16):
                new += self.add(Bi[16*i:16*i+16], RC_bin[16*i:16*i+16])
            binstr = new
        return new

    def initialization(self, hexstr):
        binary = self.hexstr2binary(hexstr)
        pad = '1' + '0'*((-len(binary)-2) % 32) + '1'
        M = binary + pad
        self.__t = int(len(M)/32)
        return M

    def absorbing(self, M):
        for i in range(self.__t):
            mi = M[32*i:32*i+32]
            Ai = self.xor(self.__cv[i], mi)
            self.__cv.insert(i+1, self.f(Ai))

    def squeezing(self, hexstr):
        H = hexstr[:32]
        for i in range(6):
            hexstr = self.f(hexstr)
            H += hexstr[:32]
        return H

    def hexdigest(self):
        M = self.initialization(self.__plainhex)
        self.absorbing(M)
        H = self.squeezing(self.__cv[self.__t])
        return self.binary2hexstr(H)


if __name__ == '__main__':
    #Have tried replacing the test string with hex, prefacing it with b.  Neither works they just make slight changes to the error.
    m = NeevaHash("Test")
    print(m.hexdigest())
