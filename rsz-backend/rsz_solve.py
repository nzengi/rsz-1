# -*- coding: utf-8 -*-
"""
@author: iceland
@credit: KV
"""
import random
import secp256k1 as ice

G = ice.scalar_multiplication(1)
N = ice.N

# ==============================================================================

def inv(a):
    return pow(a, N - 2, N)


def valid_rsz(r, s, z, pub_point):
    RP1 = ice.pub2upub('02' + hex(r)[2:].zfill(64))
    RP2 = ice.pub2upub('03' + hex(r)[2:].zfill(64))
    sdr = (s * inv(r)) % N
    zdr = (z * inv(r)) % N
    FF1 = ice.point_subtraction(ice.point_multiplication(RP1, sdr),
                               ice.scalar_multiplication(zdr))
    FF2 = ice.point_subtraction(ice.point_multiplication(RP2, sdr),
                               ice.scalar_multiplication(zdr))
    if FF1 == pub_point or FF2 == pub_point:
        return True
    else:
        return False


def getk1(r1, s1, z1, r2, s2, z2, m):
    nr = (s2 * m * r1 + z1 * r2 - z2 * r1) % N
    dr = (s1 * r2 - s2 * r1) % N
    return (nr * inv(dr)) % N


def getpvk(r1, s1, z1, r2, s2, z2, m):
    x1 = (s2 * z1 - s1 * z2 + m * s1 * s2) % N
    xi = inv((s1 * r2 - s2 * r1) % N)
    x = (x1 * xi) % N
    return x

def getx(Q):
    return int(Q[1:33].hex(), 16)
# ==============================================================================

def generate_and_solve():
    """API için kullanılacak fonksiyon"""
    pvk = random.SystemRandom().randint(1, 2 ** 256)
    Q = ice.scalar_multiplication(pvk)

    k1 = random.SystemRandom().randint(1, 2 ** 256)
    P1 = ice.scalar_multiplication(k1)
    r1 = getx(P1)
    z1 = random.SystemRandom().randint(1, 2 ** 256)
    s1 = (inv(k1) * (z1 + r1 * pvk)) % N

    k2 = random.SystemRandom().randint(1, 2 ** 256)
    P2 = ice.scalar_multiplication(k2)
    r2 = getx(P2)
    z2 = random.SystemRandom().randint(1, 2 ** 256)
    s2 = (inv(k2) * (z2 + r2 * pvk)) % N

    diff = (k2 - k1) % N
    
    # Çözümü bul
    k = getk1(r1, s1, z1, r2, s2, z2, diff)
    x = getpvk(r1, s1, z1, r2, s2, z2, diff)
    
    return {
        'true_privatekey': hex(pvk),
        'k1': hex(k1),
        'r1': hex(r1),
        's1': hex(s1),
        'z1': hex(z1),
        'k2': hex(k2),
        'r2': hex(r2),
        's2': hex(s2),
        'z2': hex(z2),
        'recovered_privatekey': hex(x)
    }
