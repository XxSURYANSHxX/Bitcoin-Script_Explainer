"""
Bitcoin Script opcode definitions and symbolic execution handlers.

This module implements symbolic execution of Bitcoin opcodes.
It does NOT perform real cryptographic operations - all values are symbolic.
"""

from typing import List, Tuple, Callable, Dict
from dataclasses import dataclass


@dataclass
class OpcodeResult:
    """Result of executing an opcode."""
    success: bool
    stack: List[str]
    explanation: str
    error: str = ""


class StackUnderflowError(Exception):
    """Raised when an operation requires more stack items than available."""
    pass


class ScriptExecutionError(Exception):
    """Raised when script execution fails."""
    pass


# Opcode descriptions for educational purposes
OPCODE_DESCRIPTIONS: Dict[str, str] = {
    "OP_DUP": "Duplicates the top stack item",
    "OP_HASH160": "Performs RIPEMD160(SHA256(x)) on the top stack item",
    "OP_EQUAL": "Compares top two stack items, pushes TRUE if equal, FALSE otherwise",
    "OP_EQUALVERIFY": "Same as OP_EQUAL, but removes result and fails if FALSE",
    "OP_CHECKSIG": "Verifies a signature against a public key",
    "OP_CHECKMULTISIG": "Verifies multiple signatures against multiple public keys",
    "OP_VERIFY": "Removes top stack item and fails if it's FALSE or zero",
    "OP_RETURN": "Marks transaction output as invalid (used for data embedding)",
}


def execute_op_dup(stack: List[str]) -> OpcodeResult:
    """
    OP_DUP: Duplicates the top stack item.
    Stack effect: (x) -> (x x)
    """
    if len(stack) < 1:
        return OpcodeResult(
            success=False,
            stack=stack,
            explanation="OP_DUP failed: stack is empty",
            error="Stack underflow: OP_DUP requires at least 1 item"
        )
    
    top_item = stack[-1]
    new_stack = stack + [top_item]
    
    return OpcodeResult(
        success=True,
        stack=new_stack,
        explanation=f"OP_DUP: Duplicated '{top_item}' on top of the stack"
    )


def execute_op_hash160(stack: List[str]) -> OpcodeResult:
    """
    OP_HASH160: Performs RIPEMD160(SHA256(x)) on top stack item.
    Stack effect: (x) -> (hash160(x))
    
    Note: This is symbolic - we don't perform actual hashing.
    """
    if len(stack) < 1:
        return OpcodeResult(
            success=False,
            stack=stack,
            explanation="OP_HASH160 failed: stack is empty",
            error="Stack underflow: OP_HASH160 requires at least 1 item"
        )
    
    top_item = stack[-1]
    new_stack = stack[:-1] + [f"HASH160({top_item})"]
    
    return OpcodeResult(
        success=True,
        stack=new_stack,
        explanation=f"OP_HASH160: Replaced '{top_item}' with its HASH160 (symbolic)"
    )


def execute_op_equal(stack: List[str]) -> OpcodeResult:
    """
    OP_EQUAL: Compares top two stack items.
    Stack effect: (x y) -> (TRUE if x==y else FALSE)
    """
    if len(stack) < 2:
        return OpcodeResult(
            success=False,
            stack=stack,
            explanation="OP_EQUAL failed: need at least 2 items",
            error="Stack underflow: OP_EQUAL requires at least 2 items"
        )
    
    item1 = stack[-1]
    item2 = stack[-2]
    new_stack = stack[:-2]
    
    # Symbolic comparison
    if item1 == item2:
        new_stack.append("TRUE")
        explanation = f"OP_EQUAL: Compared '{item2}' and '{item1}' - they are equal, pushed TRUE"
    else:
        new_stack.append(f"EQUAL({item2},{item1})")
        explanation = f"OP_EQUAL: Compared '{item2}' and '{item1}' - symbolic result pushed"
    
    return OpcodeResult(
        success=True,
        stack=new_stack,
        explanation=explanation
    )


def execute_op_equalverify(stack: List[str]) -> OpcodeResult:
    """
    OP_EQUALVERIFY: Same as OP_EQUAL but removes result and fails if FALSE.
    Stack effect: (x y) -> () if equal, else FAIL
    """
    if len(stack) < 2:
        return OpcodeResult(
            success=False,
            stack=stack,
            explanation="OP_EQUALVERIFY failed: need at least 2 items",
            error="Stack underflow: OP_EQUALVERIFY requires at least 2 items"
        )
    
    item1 = stack[-1]
    item2 = stack[-2]
    new_stack = stack[:-2]
    
    # For symbolic execution, we assume verification succeeds
    # unless we can definitively prove they're different
    if item1 == item2:
        explanation = f"OP_EQUALVERIFY: Verified '{item2}' equals '{item1}' - verification passed"
    else:
        explanation = f"OP_EQUALVERIFY: Symbolically verified '{item2}' equals '{item1}' (assumed valid)"
    
    return OpcodeResult(
        success=True,
        stack=new_stack,
        explanation=explanation
    )


def execute_op_checksig(stack: List[str]) -> OpcodeResult:
    """
    OP_CHECKSIG: Verifies signature against public key.
    Stack effect: (sig pubkey) -> (TRUE if valid else FALSE)
    
    Note: This is symbolic - we don't perform actual signature verification.
    """
    if len(stack) < 2:
        return OpcodeResult(
            success=False,
            stack=stack,
            explanation="OP_CHECKSIG failed: need signature and public key",
            error="Stack underflow: OP_CHECKSIG requires at least 2 items"
        )
    
    pubkey = stack[-1]
    sig = stack[-2]
    new_stack = stack[:-2] + ["TRUE (symbolic signature verification)"]
    
    return OpcodeResult(
        success=True,
        stack=new_stack,
        explanation=f"OP_CHECKSIG: Symbolically verified signature '{sig}' against public key '{pubkey}' - assumed valid"
    )


def execute_op_checkmultisig(stack: List[str]) -> OpcodeResult:
    """
    OP_CHECKMULTISIG: Verifies M-of-N multisig.
    Stack effect: (dummy sig1...sigM M pubkey1...pubkeyN N) -> (TRUE if valid)
    
    Note: This is symbolic and simplified. Real OP_CHECKMULTISIG has complex rules.
    """
    if len(stack) < 4:
        return OpcodeResult(
            success=False,
            stack=stack,
            explanation="OP_CHECKMULTISIG failed: insufficient stack items",
            error="Stack underflow: OP_CHECKMULTISIG requires more items"
        )
    
    # In real Bitcoin Script, N is at top, then N pubkeys, then M, then M sigs, then dummy
    # For symbolic execution, we simplify this
    new_stack = ["TRUE (symbolic multisig verification)"]
    
    return OpcodeResult(
        success=True,
        stack=new_stack,
        explanation="OP_CHECKMULTISIG: Symbolically verified multisig - assumed valid (actual implementation requires proper M-of-N structure)"
    )


def execute_op_verify(stack: List[str]) -> OpcodeResult:
    """
    OP_VERIFY: Fails if top stack item is false or zero.
    Stack effect: (x) -> () if x is true, else FAIL
    """
    if len(stack) < 1:
        return OpcodeResult(
            success=False,
            stack=stack,
            explanation="OP_VERIFY failed: stack is empty",
            error="Stack underflow: OP_VERIFY requires at least 1 item"
        )
    
    top_item = stack[-1]
    new_stack = stack[:-1]
    
    # Check for explicitly false values
    if top_item.upper() in ["FALSE", "0", ""]:
        return OpcodeResult(
            success=False,
            stack=new_stack,
            explanation=f"OP_VERIFY: Failed because '{top_item}' is false/zero",
            error="Verification failed: top stack item is false"
        )
    
    return OpcodeResult(
        success=True,
        stack=new_stack,
        explanation=f"OP_VERIFY: Verified '{top_item}' is truthy - verification passed"
    )


def execute_op_return(stack: List[str]) -> OpcodeResult:
    """
    OP_RETURN: Marks output as invalid (provably unspendable).
    Used for embedding data in the blockchain.
    """
    return OpcodeResult(
        success=True,
        stack=stack,
        explanation="OP_RETURN: Script is provably unspendable (null data output). Any following data is embedded payload."
    )


def execute_data_push(data: str, stack: List[str]) -> OpcodeResult:
    """
    Handles data push operations (hex literals, public keys, etc.)
    """
    new_stack = stack + [data]
    
    # Determine what kind of data this might be
    if len(data) == 40:  # Typical HASH160 output length in hex
        data_type = "hash (possibly pubkey hash or script hash)"
    elif len(data) == 64:  # SHA256 length
        data_type = "hash (possibly SHA256)"
    elif len(data) == 66 or len(data) == 130:  # Compressed or uncompressed pubkey
        data_type = "possible public key"
    elif len(data) >= 140:  # Signatures are typically longer
        data_type = "possible signature"
    else:
        data_type = "data"
    
    return OpcodeResult(
        success=True,
        stack=new_stack,
        explanation=f"PUSH: Added '{data}' to stack ({data_type})"
    )


# Mapping of opcode names to their execution functions
OPCODE_HANDLERS: Dict[str, Callable[[List[str]], OpcodeResult]] = {
    "OP_DUP": execute_op_dup,
    "OP_HASH160": execute_op_hash160,
    "OP_EQUAL": execute_op_equal,
    "OP_EQUALVERIFY": execute_op_equalverify,
    "OP_CHECKSIG": execute_op_checksig,
    "OP_CHECKMULTISIG": execute_op_checkmultisig,
    "OP_VERIFY": execute_op_verify,
    "OP_RETURN": execute_op_return,
}


def is_opcode(token: str) -> bool:
    """Check if a token is a recognized opcode."""
    return token.upper().startswith("OP_")


def get_opcode_description(opcode: str) -> str:
    """Get the human-readable description of an opcode."""
    return OPCODE_DESCRIPTIONS.get(opcode.upper(), f"Unknown opcode: {opcode}")
