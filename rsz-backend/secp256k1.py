import hashlib
import hmac

# Curve parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
Zero = b'\x04' + b'\x00'*64

def mod_inv(a, n):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    _, x, _ = extended_gcd(a, n)
    return (x + n) % n

def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    
    x1, y1 = p1
    x2, y2 = p2
    
    if x1 == x2 and y1 != y2:
        return None
    
    if x1 == x2:
        m = (3 * x1 * x1) * mod_inv(2 * y1, P) % P
    else:
        m = (y2 - y1) * mod_inv(x2 - x1, P) % P
    
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    
    return (x3, y3)

def scalar_multiplication(k):
    """Returns bytes representation of k*G"""
    if isinstance(k, bytes):
        k = int.from_bytes(k, 'big')
    elif isinstance(k, str):
        k = int(k, 16)
    
    result = scalar_mult(k)
    return point_to_bytes(result)

def scalar_mult(k, point=G):
    """Internal function that returns tuple representation"""
    result = None
    addend = point
    
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    
    return result

def point_to_bytes(point):
    if point is None:
        return Zero
    x, y = point
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

def bytes_to_point(pubkey_bytes):
    if pubkey_bytes == Zero:
        return None
    if pubkey_bytes[0] != 4:
        raise ValueError("Only uncompressed points supported")
    x = int.from_bytes(pubkey_bytes[1:33], 'big')
    y = int.from_bytes(pubkey_bytes[33:], 'big')
    return (x, y)

def point_addition(p1_bytes, p2_bytes):
    p1 = bytes_to_point(p1_bytes)
    p2 = bytes_to_point(p2_bytes)
    result = point_add(p1, p2)
    return point_to_bytes(result)

def point_subtraction(p1_bytes, p2_bytes):
    p1 = bytes_to_point(p1_bytes)
    p2 = bytes_to_point(p2_bytes)
    # Negate y coordinate for subtraction
    p2 = (p2[0], (-p2[1]) % P)
    result = point_add(p1, p2)
    return point_to_bytes(result)

def get_sha256(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).digest()

def pubkey_to_h160(addr_type, iscompressed, pubkey):
    return hashlib.new('ripemd160', get_sha256(pubkey)).digest()

def get_y_from_x(x, is_even):
    """Calculate y coordinate given x and parity (is_even)"""
    y_squared = (pow(x, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)  # quadratic residue
    
    if bool(y & 1) != bool(not is_even):
        y = (-y) % P
        
    return y

def pub2upub(pub_hex):
    """Convert compressed/uncompressed pubkey to uncompressed format"""
    if len(pub_hex) > 70:  # already uncompressed
        return bytes.fromhex(pub_hex)
        
    # Compressed format
    x = int(pub_hex[2:], 16)
    is_even = pub_hex.startswith('02')
    y = get_y_from_x(x, is_even)
    
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

def point_to_cpub(pubkey_bytes):
    """Convert point to compressed pubkey format"""
    if pubkey_bytes == Zero:
        return '00' * 33
        
    point = bytes_to_point(pubkey_bytes)
    if point is None:
        return '00' * 33
        
    x, y = point
    prefix = '02' if y % 2 == 0 else '03'
    return prefix + hex(x)[2:].zfill(64)

def to_cpub(pub_hex):
    """Convert any pubkey format to compressed"""
    if len(pub_hex) <= 70:  # already compressed
        return pub_hex
        
    pubkey_bytes = bytes.fromhex(pub_hex)
    return point_to_cpub(pubkey_bytes)

def point_multiplication(pubkey_bytes, k):
    """Multiply a point by scalar k"""
    if isinstance(k, str):
        k = int(k, 16)
    elif isinstance(k, bytes):
        k = int.from_bytes(k, 'big')
    
    point = bytes_to_point(pubkey_bytes)
    if point is None:
        return Zero
        
    result = scalar_mult(k, point)
    return point_to_bytes(result) 