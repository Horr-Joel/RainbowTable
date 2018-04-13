import random
from SM3 import sm3
from RainbowTable import match

keys = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-+=[]<>/?|'
num = 1000
found = 0

# 随机生成num个待破解Hash值
for i in range(num):
    P = ''
    # 随机生成5位初始密码
    for j in range(5):
        index = random.randint(0, 81)
        P += keys[index]

    Q = sm3(P)

    if match(Q,1001) != -1:
        found += 1

print("Random %d passwd, Crack rate is %f" % (num, found / num))
