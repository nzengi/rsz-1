import rsz_solve
import rsz_rdiff_scan
import LLL_nonce_leakage
import getz_input
import json

def test_rsz_solve():
    print("\n=== Testing RSZ Solve ===")
    try:
        result = rsz_solve.generate_and_solve()
        print("Generated Private Key:", result['true_privatekey'])
        print("Recovered Private Key:", result['recovered_privatekey'])
        assert result['true_privatekey'] == result['recovered_privatekey'], "Private key recovery failed"
        print("✓ RSZ Solve test passed")
    except Exception as e:
        print("✗ RSZ Solve test failed:", str(e))

def test_tx_info():
    print("\n=== Testing Transaction Info ===")
    # First Bitcoin transaction ever (block 170)
    test_txid = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
    try:
        result = getz_input.process_txid(test_txid)
        print("Transaction inputs:", result['total_inputs'])
        for inp in result['inputs']:
            print(f"\nInput {inp['input_index']}:")
            print("R:", inp['r'])
            print("S:", inp['s'])
            print("Z:", inp['z'])
            print("PubKey:", inp['pubkey'])
        print("✓ Transaction Info test passed")
    except Exception as e:
        print("✗ Transaction Info test failed:", str(e))

def test_address_scan():
    print("\n=== Testing Address Scanner ===")
    # Legacy address from an old transaction
    test_address = "1HQ3Go3ggs8pFnXuHVHRytPCq5fGG8Hbhx"  # Satoshi'nin kullandığı bir adres
    try:
        result = rsz_rdiff_scan.scan_address(test_address)
        print("Results:", result)
        print("✓ Address Scanner test passed")
    except Exception as e:
        print("✗ Address Scanner test failed:", str(e))

def test_nonce_leakage():
    print("\n=== Testing Nonce Leakage ===")
    try:
        result = LLL_nonce_leakage.analyze(56)
        print("Results:", result)
        print("✓ Nonce Leakage test passed")
    except Exception as e:
        print("✗ Nonce Leakage test failed:", str(e))

def test_multiple_addresses():
    print("\n=== Testing Multiple Address Types ===")
    addresses = [
        # Legacy
        "1HQ3Go3ggs8pFnXuHVHRytPCq5fGG8Hbhx",
        # SegWit
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        # Native SegWit
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    ]
    
    for addr in addresses:
        print(f"\nTesting address: {addr}")
        try:
            result = rsz_rdiff_scan.scan_address(addr)
            print(f"Found {result['total_transactions']} transactions")
            if result['transactions']:
                print("First transaction details:")
                print(json.dumps(result['transactions'][0], indent=2))
        except Exception as e:
            print(f"Error scanning address: {str(e)}")

if __name__ == "__main__":
    print("Starting backend tests...")
    test_rsz_solve()
    test_tx_info()
    test_address_scan()
    test_multiple_addresses()
    test_nonce_leakage()
    print("\nTests completed.") 