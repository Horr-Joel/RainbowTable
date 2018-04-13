# encoding:utf8
import random
from SM3 import sm3
import hashlib
from multiprocessing import Process
import os

keys = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-+=[]<>/?|'
tran16to2 = {'0': '0000', '1': '0001', '2': '0010', '3': '0011', '4': '0100', '5': '0101', '6': '0110', '7': '0111',
             '8': '1000',
             '9': '1001', 'a': '1010', 'b': '1011', 'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'}


def R(hash):
    hash = hash.encode('utf8')
    md5 = hashlib.md5(hash).hexdigest()

    bit = bin(int(md5, 16))[-35:]
    P = ''

    # 35位分为5个7位2进制，转换为5个10进制，从keys取数
    for i in range(5):
        tmp = ''
        for j in range(7):
            tmp += bit[i * 7 + j]
        tmp = int(tmp, 2)
        P += keys[tmp % 82]
    return P


# 单线程生成彩虹表
def single_genTable(len, num, filename):
    table = []
    print('start generate %s' % filename)
    # 输入长度必须为奇数
    if len % 2 != 1:
        print("gentable error")
        return 0
    # 依次生成num行
    for i in range(num):
        P = ''
        # 随机生成5位初始密码
        for j in range(5):
            index = random.randint(0, 81)
            P += keys[index]

        line = P + ','
        hash = ''
        # 计算len-1次得到链尾
        for k in range(len - 1):
            if k % 2 == 0:
                hash = sm3(P)
            else:
                P = R(hash)
        line += P
        table.append(line)

    f = open(filename, 'w')
    for line in table:
        f.write(line + '\n')
    f.close()
    print("Generate Table %s succeed!" % filename)


# 四线程生成彩虹表
def multi_genTable(len, num):
    # 4个线程生成4个链长为len，行数为num/4的csv文件
    t1 = Process(target=single_genTable, args=(len, int(num / 4), "part1.csv"))
    t2 = Process(target=single_genTable, args=(len, int(num / 4), "part2.csv"))
    t3 = Process(target=single_genTable, args=(len, int(num / 4), "part3.csv"))
    t4 = Process(target=single_genTable, args=(len, int(num / 4), "part4.csv"))

    # 开始运行线程
    t1.start()
    t2.start()
    t3.start()
    t4.start()

    # 等待各个线程运行完毕
    t1.join()
    t2.join()
    t3.join()
    t4.join()

    # 如果上次运行生成了RainbowTable.csv，则删除上次运行生成的文件
    if os.path.exists("RainbowTable.csv"):
        os.remove("RainbowTable.csv")

    # 将4个csv合并为一个num行的csv，为最终彩虹表
    for i in ["part1.csv", "part2.csv", "part3.csv", "part4.csv"]:
        fr = open(i, 'r').read()
        with open('RainbowTable.csv', 'a') as f:
            f.write(fr)
    print('Generate Rainbow Table succeed！')


# 在生成彩虹表后匹配函数
def match(hash, len):
    # 先读取彩虹表
    table = []
    f = open('RainbowTable.csv', 'r')
    lines = f.readlines()
    for line in lines:
        start, end = line.strip().split(',')
        table.append([start, end])
    del lines
    # 对于每行最多找(len-1)/2轮
    passwd = None
    find = False
    # 先验证第一轮,此时hash做R运算后的值与链尾比较
    P = R(hash)
    count = int((len - 1) / 2 - 1)
    print(count)
    for start, end in table:
        if P == end:
            find = True
            # 循环(len-1)/2 - 1次 （H、R）函数得到匹配的hash前一个明文Q
            Q = start
            for i in range(count):
                H = sm3(Q)
                Q = R(H)

            # 验证明密文是否对应
            if sm3(Q) == hash:
                passwd = Q
                return passwd
    # if find == False:
    #     print('not match in 1 round')
    # else:
    #     print("match in 1 round")
    # 第一轮没找到继续找
    for i in range(count):
        find = False
        # 每轮循环增加一次（SM3，R）运算
        Q = sm3(P)
        P = R(Q)
        for start, end in table:
            if P == end:
                find = True
                # 循环count-i-1次 （H、R）函数得到匹配的hash前一个明文Q
                Q = start
                for k in range(count - i - 1):
                    H = sm3(Q)
                    Q = R(H)
                # 验证明密文是否对应
                if sm3(Q) == hash:
                    passwd = Q
                    return passwd
        # if find == False:
        #     print("not match in %d round" % (i + 2))
        # else:
        #     print("match in %d round" % (i + 2))
    return -1


if __name__ == '__main__':
    # 如果已有彩虹表且名为RainbowTable.csv，则将下面生成函数注释
    # 4线程生成彩虹表
    multi_genTable(1001, 4300000)

    # 执行彩虹表搜索匹配，此表链长为1001
    re = match('bb0c13584f3dd789234cd3e6cf8247e0ab8ce8be4574127ecdffffb0eaeb76cc', 1001)
    if re == -1:
        print("no password found")
    else:
        print(re)
