# -*- coding: utf-8 -*-
"""
@author: iceland
"""
import sys
import secp256k1 as ice
from urllib.request import urlopen

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

def process_txid(txid):
    """Process transaction by txid"""
    try:
        htmlfile = urlopen(f"https://blockchain.info/rawtx/{txid}?format=hex", timeout=20)
        rawtx = htmlfile.read().decode('utf-8')
        return process_rawtx(rawtx)
    except Exception as e:
        raise Exception(f"Error processing txid: {str(e)}")

def process_rawtx(rawtx):
    """Process raw transaction"""
    try:
        m = parseTx(rawtx)
        e = getSignableTxn(m)
        
        results = []
        for i in range(len(e)):
            tx_info = {
                'input_index': i,
                'r': e[i][0],
                's': e[i][1],
                'z': e[i][2],
                'pubkey': e[i][3]
            }
            results.append(tx_info)
            
        return {
            'total_inputs': len(results),
            'inputs': results
        }
        
    except Exception as e:
        raise Exception(f"Error processing raw transaction: {str(e)}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Get ECDSA Signature r,s,z values from Bitcoin transaction')
    parser.add_argument("-txid", help="Transaction ID to analyze")
    parser.add_argument("-rawtx", help="Raw transaction hex to analyze")
    args = parser.parse_args()
    
    if args.txid:
        result = process_txid(args.txid)
    elif args.rawtx:
        result = process_rawtx(args.rawtx)
    else:
        parser.print_help()
        sys.exit(1)
        
    import json
    print(json.dumps(result, indent=2))

