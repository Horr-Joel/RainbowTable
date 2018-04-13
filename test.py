import random
from SM3 import sm3
from RainbowTable import R
from multiprocessing import Process

keys = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-+=[]<>/?|'
length = 1001
table = []
total = 100
found = 0


# 重写匹配函数，将读取csv文件放在函数体外以便多次匹配
def match(hash):
    # 对于每行最多找(len-1)/2轮
    # 先验证第一轮,此时hash做R运算后的值与链尾比较
    P = R(hash)
    count = int((length - 1) / 2 - 1)
    for start, end in table:
        if P == end:

            # 循环(len-1)/2 - 1次 （H、R）函数得到匹配的hash前一个明文Q
            Q = start
            for i in range(count):
                H = sm3(Q)
                Q = R(H)

            # 验证明密文是否对应
            if sm3(Q) == hash:
                return Q

    # 第一轮没找到继续找
    for i in range(count):
        # 每轮循环增加一次（SM3，R）运算
        Q = sm3(P)
        P = R(Q)
        for start, end in table:
            if P == end:
                # 循环count-i-1次 （H、R）函数得到匹配的hash前一个明文Q
                Q = start
                for k in range(count - i - 1):
                    H = sm3(Q)
                    Q = R(H)
                # 验证明密文是否对应
                if sm3(Q) == hash:
                    return Q
    return -1


if __name__ == '__main__':

    # 读取彩虹表

    f = open('RainbowTable.csv', 'r')
    lines = f.readlines()
    for line in lines:
        start, end = line.strip().split(',')
        table.append([start, end])
    del lines

    # 随机生成num个待破解Hash值
    for i in range(total):
        P = ''
        # 随机生成5位初始密码
        for j in range(5):
            index = random.randint(0, 81)
            P += keys[index]
        Q = sm3(P)
        if match(Q) != -1:
            found += 1
        print(i)
    print("Random %d passwd, Crack rate is %f" % (total, found / total))
