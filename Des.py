# -*- coding: utf8 -*-
import base64
import random,string
                                        # 初始置换IP
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

                                        # Key 初始置换选择1
CP_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

                                        # KEY 置换选择2
CP_2 = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]

                                        # 数据块 扩展置换
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

                                        # SBOX
S_BOX = [

    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
     ],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
     ],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
     ],

    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
     ],

    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
     ],

    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
     ],

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
     ],

    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
     ]
]

                                         # P盒置换
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

                                         # 初始逆置换
IP_1 = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]

                                         # 确定每轮产生键的移位矩阵
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def string_to_bit_array(text):           # 字符串-->bit数组
    array = list()
    for char in text:
        binval = binvalue(char, 8)       # 获得每个字符的二进制
        array.extend([int(x) for x in list(binval)])
    return array


def bit_array_to_string(array):          # bit数组-->字符串
    res = ''.join([chr(int(y, 2)) for y in [''.join([str(x) for x in bytes]) for bytes in nsplit(array, 8)]])
    return res


def binvalue(val, bitsize):              # 以给定大小的字符返回二进制值
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise Exception("binary value larger than the expected size")
    while len(binval) < bitsize:
        binval = "0" + binval
    return binval


def nsplit(s, n):                        # 将列表拆分为大小为'n'的子列表
    return [s[k:k + n] for k in range(0, len(s), n)]


def getRandomString(slen=8):             # 获得key的随机序列
    return ''.join(random.sample(string.ascii_letters + string.digits, slen))

ENCRYPT = 1
DECRYPT = 0

class Des():
    def __init__(self):
        self.password = None             # 存放初始key
        self.text = None                 # 存放明文
        self.keys = list()               # 存放key值列表集合

    def run(self, key, text, action, padding):
        if len(key) < 8:
            raise Exception("Key Should be 8 bytes long")
        elif len(key) > 8:
                    key = key[:8]        # 如果key的长度大于8，则取其前8位字节

        self.password = key
        self.text = text

        if padding and action == ENCRYPT:
            self.addPadding()
        elif len(self.text) % 8 != 0:    # 数据的大小一定是 8bytes 大小的倍数
            raise Exception("Data size should be multiple of 8")

        self.generatekeys()              # 统计计算所有的key值，存入keys列表
        text_blocks = nsplit(self.text, 8)      # 数据的分片每8个字节一组
        result = list()
        for block in text_blocks:               # 遍历所有数据块
            block = string_to_bit_array(block)
            block = self.permut(block, IP)      # 数据块的初始置换
            g, d = nsplit(block, 32)            # 数据块分片 g(LEFT), d(RIGHT)
            tmp = None
            for i in range(16):                 # 16轮循环
                d_e = self.expand(d, E)         # d(RIGHT)的扩展 32bit-->48bit
                if action == ENCRYPT:
                    tmp = self.xor(self.keys[i], d_e)
                else:
                    tmp = self.xor(self.keys[15 - i], d_e)  # 如果是解密的话先使用最后的key
                tmp = self.substitute(tmp)                  # S盒代换 48bit-->32bit
                tmp = self.permut(tmp, P)                   # P盒置换
                tmp = self.xor(g, tmp)
                g = d
                d = tmp
            result += self.permut(d + g, IP_1)              # 数据块的初始逆置换
        final_res = bit_array_to_string(result)
        if padding and action == DECRYPT:
            return self.removePadding(final_res)            # 如果解密和填充为真，则删除填充
        else:
            return final_res

    def substitute(self, d_e):                              # S盒代换
        subblocks = nsplit(d_e, 6)                          # 将位数组分割为6位的子列表
        result = list()
        for i in range(len(subblocks)):                     # 遍历子列表
            block = subblocks[i]
            row = int(str(block[0]) + str(block[5]), 2)     # 得到第一位和最后一个位表示的行
            column = int(''.join([str(x) for x in block[1:][:-1]]), 2)  # 得到第二、三、四、五位表示的列
            val = S_BOX[i][row][column]                     # 取为本轮分配的SBOX[i]中的值
            bin = binvalue(val, 4)                          # 将值转换为二进制
            result += [int(x) for x in bin]                 # 将二进制值添加到结果列表中
        return result

    def permut(self, block, table):                 # 置换(本程序中充当基本置换、压缩置换的角色)
        return [block[x - 1] for x in table]

    def expand(self, block, table):                 # 扩展置换
        return [block[x - 1] for x in table]

    def xor(self, t1, t2):                          # 应用xor并返回结果列表
        return [x ^ y for x, y in zip(t1, t2)]

    def generatekeys(self):                         # 统计计算所有key值的算法
        self.keys = []
        key = string_to_bit_array(self.password)
        key = self.permut(key, CP_1)                # 置换选择1 初始化key 64bit-->56bit
        g, d = nsplit(key, 28)                      # 分片 (g->LEFT),(d->RIGHT)
        for i in range(16):                         # 16轮循环
            g, d = self.shift(g, d, SHIFT[i])       # (g->LEFT),(d->RIGHT)分别进行移位操作
            tmp = g + d                             # 合并 28bit+28bit-->56bit
            self.keys.append(self.permut(tmp, CP_2))# 置换选择2 56bit-->48bit

    def shift(self, g, d, n):                       # 每轮key值产生所需的函数
        return g[n:] + g[:n], d[n:] + d[:n]

    def addPadding(self):                           # 使用 PKCS5 进行数据的填充,不管是否是BlockSize的整数倍都需要进行填充
        pad_len = 8 - (len(self.text) % 8)
        self.text += pad_len * chr(pad_len)

    def removePadding(self, data):                  # 删除纯文本的填充
        pad_len = ord(data[-1])
        return data[:-pad_len]

    def encrypt(self, key, text, padding):          # DES 加密函数
        return self.run(key, text, ENCRYPT, padding)

    def decrypt(self, key, text, padding):          # DES 解密函数
        return self.run(key, text, DECRYPT, padding)

if __name__ == '__main__':
    key = getRandomString()
    with open('text.txt','r+') as fr:
        text = (fr.read())                 # 从 'text.txt' 文件中读取加密文本
    D = Des()
    C = (base64.b64encode((D.encrypt(key, text, True)).encode("utf8"))).decode()#加密
    C1 = (base64.b64decode(C)).decode()
    P = D.decrypt(key, C1, True)             # 解密
    with open('key.txt','w+') as fwk:        # 存储密钥
        fwk.write(key)
    with open('ciphertext.txt','w+') as fwc: # 存储密文
        fwc.write(C)
    with open('plaintext.txt','w+') as fwp:  # 存储明文
        fwp.writelines(P)
    print('********************* Des Encryption and Decryption *********************')
    print('*                                                                       *')
    print('*                                                                       *')
    print('*                                                                       *')
    print('*                Key: 存储于 < key.txt > 文件中.                          *')
    print('*                                                                       *')
    print('*                Ciphertext: 存储于 < ciphertext.txt > 文件中.            *')
    print('*                                                                       *')
    print('*                Plaintext: 存储于 < plaintext.txt > 文件中.              *')
    print('*                                                                       *')
    print('*                                                                       *')
    print('*                                                                       *')
    print('*************************************************************************')