"""
Bitcoin Script type detection module.

Detects common Bitcoin script patterns and categorizes them.
Supports legacy, P2SH, and SegWit script types.
"""

from typing import List, Tuple


# Script type constants
P2PKH = "P2PKH (Pay-to-Public-Key-Hash)"
P2SH = "P2SH (Pay-to-Script-Hash)"
P2PK = "P2PK (Pay-to-Public-Key)"
MULTISIG = "Multisig (Multi-signature)"
NULL_DATA = "Null Data (OP_RETURN)"
P2WPKH = "P2WPKH (Native SegWit)"
P2WSH = "P2WSH (SegWit Script Hash)"
P2TR = "P2TR (Taproot)"
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
        return P2PKH, "This is a Pay-to-Public-Key-Hash script. It requires a signature and public key that hashes to the embedded 20-byte hash. Most common script type for Bitcoin addresses starting with '1'."
    
    # Check for P2SH pattern
    # Standard: OP_HASH160 <scripthash> OP_EQUAL
    if is_p2sh(normalized):
        return P2SH, "This is a Pay-to-Script-Hash script. The spender must provide a redeem script that hashes to the embedded hash. Used for multisig and wrapped SegWit (addresses starting with '3')."
    
    # Check for P2WPKH pattern (Native SegWit v0)
    # Standard: OP_0 <20-byte-pubkeyhash>
    if is_p2wpkh(normalized):
        return P2WPKH, "This is a Native SegWit Pay-to-Witness-Public-Key-Hash script. It provides lower fees and better security than P2PKH. Addresses start with 'bc1q'."
    
    # Check for P2WSH pattern (Native SegWit v0)
    # Standard: OP_0 <32-byte-scripthash>
    if is_p2wsh(normalized):
        return P2WSH, "This is a Native SegWit Pay-to-Witness-Script-Hash script. Similar to P2SH but with SegWit benefits. Addresses start with 'bc1q'."
    
    # Check for P2TR pattern (Taproot v1)
    # Standard: OP_1 <32-byte-pubkey>
    if is_p2tr(normalized):
        return P2TR, "This is a Taproot (Pay-to-Taproot) script. It uses Schnorr signatures and enables advanced scripting features. Addresses start with 'bc1p'."
    
    # Check for P2PK pattern
    # Standard: <pubkey> OP_CHECKSIG
    if is_p2pk(normalized):
        return P2PK, "This is a Pay-to-Public-Key script. An early Bitcoin script type that exposes the public key directly. Rarely used in modern transactions."
    
    # Check for Multisig pattern
    # Standard: M <pubkey1> <pubkey2> ... <pubkeyN> N OP_CHECKMULTISIG
    if is_multisig(normalized):
        m, n = get_multisig_params(normalized)
        if m and n:
            return MULTISIG, f"This is a {m}-of-{n} multi-signature script. It requires {m} valid signatures from {n} possible public keys to spend."
        return MULTISIG, "This is a multi-signature script requiring M-of-N signatures to spend."
    
    # Check for partial matches
    if "OP_CHECKMULTISIG" in normalized:
        return MULTISIG, "This appears to be a multisig-related script, but the pattern is non-standard."
    
    if "OP_CHECKSIG" in normalized:
        return UNKNOWN, "This script uses signature verification but doesn't match standard patterns."
    
    # Check if it looks like a witness program
    if len(normalized) == 2 and normalized[0] in ["OP_0", "OP_1", "OP_2", "0", "1", "2"]:
        return UNKNOWN, "This may be a witness program (SegWit) with non-standard witness data length."
    
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


def is_p2wpkh(tokens: List[str]) -> bool:
    """
    Check if tokens match P2WPKH pattern (Native SegWit v0).
    Pattern: OP_0 <20-byte-pubkeyhash>
    The hash should be exactly 40 hex characters (20 bytes).
    """
    if len(tokens) != 2:
        return False
    
    # Check for version 0 witness program
    if tokens[0] not in ["OP_0", "0", "OP_FALSE"]:
        return False
    
    # Check for 20-byte hash (40 hex chars)
    witness_data = tokens[1]
    if witness_data.startswith("OP_"):
        return False
    
    # Must be exactly 40 hex characters for P2WPKH
    return len(witness_data) == 40 and all(c in '0123456789abcdefABCDEF' for c in witness_data)


def is_p2wsh(tokens: List[str]) -> bool:
    """
    Check if tokens match P2WSH pattern (Native SegWit v0).
    Pattern: OP_0 <32-byte-scripthash>
    The hash should be exactly 64 hex characters (32 bytes).
    """
    if len(tokens) != 2:
        return False
    
    # Check for version 0 witness program
    if tokens[0] not in ["OP_0", "0", "OP_FALSE"]:
        return False
    
    # Check for 32-byte hash (64 hex chars)
    witness_data = tokens[1]
    if witness_data.startswith("OP_"):
        return False
    
    # Must be exactly 64 hex characters for P2WSH
    return len(witness_data) == 64 and all(c in '0123456789abcdefABCDEF' for c in witness_data)


def is_p2tr(tokens: List[str]) -> bool:
    """
    Check if tokens match P2TR pattern (Taproot v1).
    Pattern: OP_1 <32-byte-x-only-pubkey>
    The pubkey should be exactly 64 hex characters (32 bytes).
    """
    if len(tokens) != 2:
        return False
    
    # Check for version 1 witness program
    if tokens[0] not in ["OP_1", "1", "OP_TRUE"]:
        return False
    
    # Check for 32-byte x-only pubkey (64 hex chars)
    witness_data = tokens[1]
    if witness_data.startswith("OP_"):
        return False
    
    # Must be exactly 64 hex characters for P2TR
    return len(witness_data) == 64 and all(c in '0123456789abcdefABCDEF' for c in witness_data)


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
    """
    if len(tokens) < 4:
        return False
    
    if tokens[-1] != "OP_CHECKMULTISIG":
        return False
    
    first = tokens[0]
    second_last = tokens[-2]
    
    return is_small_num(first) and is_small_num(second_last)


def is_small_num(token: str) -> bool:
    """Check if token represents a small number (0-16)."""
    if token.isdigit() and 0 <= int(token) <= 16:
        return True
    return token.upper() in [
        "OP_0", "OP_1", "OP_2", "OP_3", "OP_4", "OP_5",
        "OP_6", "OP_7", "OP_8", "OP_9", "OP_10", "OP_11",
        "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
        "OP_FALSE", "OP_TRUE"
    ]


def parse_small_num(token: str) -> int:
    """Parse a small number token to integer."""
    if token.isdigit():
        return int(token)
    
    mapping = {
        "OP_0": 0, "OP_FALSE": 0,
        "OP_1": 1, "OP_TRUE": 1,
        "OP_2": 2, "OP_3": 3, "OP_4": 4, "OP_5": 5,
        "OP_6": 6, "OP_7": 7, "OP_8": 8, "OP_9": 9,
        "OP_10": 10, "OP_11": 11, "OP_12": 12, "OP_13": 13,
        "OP_14": 14, "OP_15": 15, "OP_16": 16
    }
    return mapping.get(token.upper(), -1)


def get_multisig_params(tokens: List[str]) -> Tuple[int, int]:
    """Extract M and N from multisig tokens."""
    if len(tokens) < 4:
        return None, None
    
    m = parse_small_num(tokens[0])
    n = parse_small_num(tokens[-2])
    
    if m > 0 and n > 0 and m <= n:
        return m, n
    return None, None


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
            "example_address_prefix": "1",
            "introduced": "Genesis (2009)",
            "witness_version": None
        },
        P2SH: {
            "name": "Pay-to-Script-Hash",
            "abbreviation": "P2SH",
            "usage": "Used for multisig, SegWit wrapped, and complex scripts",
            "security": "Script conditions must be satisfied to spend",
            "example_address_prefix": "3",
            "introduced": "BIP-16 (2012)",
            "witness_version": None
        },
        P2WPKH: {
            "name": "Pay-to-Witness-Public-Key-Hash",
            "abbreviation": "P2WPKH",
            "usage": "Native SegWit for single-sig, lower fees than P2PKH",
            "security": "Same as P2PKH with witness segregation",
            "example_address_prefix": "bc1q",
            "introduced": "BIP-141 (2017)",
            "witness_version": 0
        },
        P2WSH: {
            "name": "Pay-to-Witness-Script-Hash",
            "abbreviation": "P2WSH",
            "usage": "Native SegWit for complex scripts like multisig",
            "security": "Same as P2SH with witness segregation",
            "example_address_prefix": "bc1q",
            "introduced": "BIP-141 (2017)",
            "witness_version": 0
        },
        P2TR: {
            "name": "Pay-to-Taproot",
            "abbreviation": "P2TR",
            "usage": "Taproot outputs with Schnorr signatures, MAST support",
            "security": "Enhanced privacy and scripting capabilities",
            "example_address_prefix": "bc1p",
            "introduced": "BIP-341 (2021)",
            "witness_version": 1
        },
        P2PK: {
            "name": "Pay-to-Public-Key",
            "abbreviation": "P2PK",
            "usage": "Early Bitcoin transactions, now rarely used",
            "security": "Less private than P2PKH as pubkey is exposed",
            "example_address_prefix": "N/A (no address format)",
            "introduced": "Genesis (2009)",
            "witness_version": None
        },
        MULTISIG: {
            "name": "Multi-signature",
            "abbreviation": "Multisig",
            "usage": "Requires M-of-N signatures to spend",
            "security": "Enhanced security through key distribution",
            "example_address_prefix": "Usually wrapped in P2SH",
            "introduced": "BIP-11 (2011)",
            "witness_version": None
        },
        NULL_DATA: {
            "name": "Null Data / OP_RETURN",
            "abbreviation": "OP_RETURN",
            "usage": "Embedding arbitrary data in the blockchain",
            "security": "Provably unspendable output",
            "example_address_prefix": "N/A (not spendable)",
            "introduced": "Bitcoin 0.9 (2014)",
            "witness_version": None
        },
        UNKNOWN: {
            "name": "Unknown / Custom",
            "abbreviation": "Custom",
            "usage": "Non-standard script patterns",
            "security": "Depends on script logic",
            "example_address_prefix": "N/A",
            "introduced": "N/A",
            "witness_version": None
        }
    }
    
    return info.get(script_type, info[UNKNOWN])


def get_all_script_types() -> List[dict]:
    """Get information about all supported script types."""
    types = [P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2PK, MULTISIG, NULL_DATA]
    return [{"type": t, **get_script_type_info(t)} for t in types]
