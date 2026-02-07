"""
Bitcoin Script type detection module.

Detects common Bitcoin script patterns and categorizes them.
"""

from typing import List, Tuple


# Script type constants
P2PKH = "P2PKH (Pay-to-Public-Key-Hash)"
P2SH = "P2SH (Pay-to-Script-Hash)"
P2PK = "P2PK (Pay-to-Public-Key)"
MULTISIG = "Multisig (Multi-signature)"
NULL_DATA = "Null Data (OP_RETURN)"
UNKNOWN = "Unknown / Custom Script"


def detect_script_type(tokens: List[str]) -> Tuple[str, str]:
    """
    Detect the type of Bitcoin Script based on token pattern.
    
    Args:
        tokens: List of script tokens
        
    Returns:
        Tuple of (script_type, description)
    """
    if not tokens:
        return UNKNOWN, "Empty script"
    
    # Normalize tokens for comparison
    normalized = [t.upper() if t.upper().startswith("OP_") else t for t in tokens]
    
    # Check for OP_RETURN (Null Data)
    if normalized[0] == "OP_RETURN":
        return NULL_DATA, "This is a null data output used for embedding data in the blockchain. It is provably unspendable."
    
    # Check for P2PKH pattern
    # Standard: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
    if is_p2pkh(normalized):
        return P2PKH, "This is a Pay-to-Public-Key-Hash script. It requires a signature and public key that hashes to the embedded hash."
    
    # Check for P2SH pattern
    # Standard: OP_HASH160 <scripthash> OP_EQUAL
    if is_p2sh(normalized):
        return P2SH, "This is a Pay-to-Script-Hash script. The spender must provide a script that hashes to the embedded hash."
    
    # Check for P2PK pattern
    # Standard: <pubkey> OP_CHECKSIG
    if is_p2pk(normalized):
        return P2PK, "This is a Pay-to-Public-Key script. It requires only a valid signature from the specified public key."
    
    # Check for Multisig pattern
    # Standard: M <pubkey1> <pubkey2> ... <pubkeyN> N OP_CHECKMULTISIG
    if is_multisig(normalized):
        return MULTISIG, "This is a multi-signature script requiring M-of-N signatures to spend."
    
    # Check for partial matches
    if "OP_CHECKMULTISIG" in normalized:
        return MULTISIG, "This appears to be a multisig-related script, but the pattern is non-standard."
    
    if "OP_CHECKSIG" in normalized:
        return UNKNOWN, "This script uses signature verification but doesn't match standard patterns."
    
    return UNKNOWN, "This is a custom or non-standard script that doesn't match known patterns."


def is_p2pkh(tokens: List[str]) -> bool:
    """
    Check if tokens match P2PKH pattern.
    Pattern: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    """
    if len(tokens) != 5:
        return False
    
    return (
        tokens[0] == "OP_DUP" and
        tokens[1] == "OP_HASH160" and
        not tokens[2].startswith("OP_") and  # This should be the hash
        tokens[3] == "OP_EQUALVERIFY" and
        tokens[4] == "OP_CHECKSIG"
    )


def is_p2sh(tokens: List[str]) -> bool:
    """
    Check if tokens match P2SH pattern.
    Pattern: OP_HASH160 <20-byte-hash> OP_EQUAL
    """
    if len(tokens) != 3:
        return False
    
    return (
        tokens[0] == "OP_HASH160" and
        not tokens[1].startswith("OP_") and  # This should be the hash
        tokens[2] == "OP_EQUAL"
    )


def is_p2pk(tokens: List[str]) -> bool:
    """
    Check if tokens match P2PK pattern.
    Pattern: <pubkey> OP_CHECKSIG
    """
    if len(tokens) != 2:
        return False
    
    return (
        not tokens[0].startswith("OP_") and  # This should be the pubkey
        tokens[1] == "OP_CHECKSIG"
    )


def is_multisig(tokens: List[str]) -> bool:
    """
    Check if tokens match bare multisig pattern.
    Pattern: <M> <pubkey1> ... <pubkeyN> <N> OP_CHECKMULTISIG
    
    Note: This is a simplified check. Real multisig uses OP_1, OP_2, etc.
    for M and N values in standard implementations.
    """
    if len(tokens) < 4:
        return False
    
    if tokens[-1] != "OP_CHECKMULTISIG":
        return False
    
    # Check if we have what looks like M at start and N before OP_CHECKMULTISIG
    # In standard scripts, these would be OP_1, OP_2, etc.
    first = tokens[0]
    second_last = tokens[-2]
    
    # Check for numeric-looking values or OP_n opcodes
    def is_small_num(t):
        return t.isdigit() or t.upper() in [
            "OP_0", "OP_1", "OP_2", "OP_3", "OP_4", "OP_5",
            "OP_6", "OP_7", "OP_8", "OP_9", "OP_10", "OP_11",
            "OP_12", "OP_13", "OP_14", "OP_15", "OP_16"
        ]
    
    return is_small_num(first) and is_small_num(second_last)


def get_script_type_info(script_type: str) -> dict:
    """
    Get detailed information about a script type.
    
    Args:
        script_type: One of the script type constants
        
    Returns:
        Dictionary with detailed information
    """
    info = {
        P2PKH: {
            "name": "Pay-to-Public-Key-Hash",
            "abbreviation": "P2PKH",
            "usage": "Most common type for regular Bitcoin addresses (starting with 1)",
            "security": "Requires knowledge of private key to spend",
            "example_address_prefix": "1"
        },
        P2SH: {
            "name": "Pay-to-Script-Hash",
            "abbreviation": "P2SH",
            "usage": "Used for multisig, SegWit wrapped, and complex scripts",
            "security": "Script conditions must be satisfied to spend",
            "example_address_prefix": "3"
        },
        P2PK: {
            "name": "Pay-to-Public-Key",
            "abbreviation": "P2PK",
            "usage": "Early Bitcoin transactions, now rarely used",
            "security": "Less private than P2PKH as pubkey is exposed",
            "example_address_prefix": "N/A (no address format)"
        },
        MULTISIG: {
            "name": "Multi-signature",
            "abbreviation": "Multisig",
            "usage": "Requires M-of-N signatures to spend",
            "security": "Enhanced security through key distribution",
            "example_address_prefix": "Usually wrapped in P2SH"
        },
        NULL_DATA: {
            "name": "Null Data / OP_RETURN",
            "abbreviation": "OP_RETURN",
            "usage": "Embedding arbitrary data in the blockchain",
            "security": "Provably unspendable output",
            "example_address_prefix": "N/A (not spendable)"
        },
        UNKNOWN: {
            "name": "Unknown / Custom",
            "abbreviation": "Custom",
            "usage": "Non-standard script patterns",
            "security": "Depends on script logic",
            "example_address_prefix": "N/A"
        }
    }
    
    return info.get(script_type, info[UNKNOWN])
