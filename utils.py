from subprocess import Popen, PIPE


def command(x):
    return str(Popen(x.split(' '), stdout=PIPE).communicate()[0])


def reset(src, dst, sport=10000, dport=80):
    send(IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="R"))


def combine(data):
    res = ""
    keys = sorted(data.keys())
    pre_k = None
    for k in keys:
        res += str(data[k])
        if pre_k and k - pre_k != len(data[k]):
            print "Lost packet between %d and %d" % (pre_k, k)
        pre_k = k
    return res

