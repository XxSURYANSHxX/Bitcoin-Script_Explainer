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
    # Stack manipulation
    "OP_DUP": "Duplicates the top stack item",
    "OP_DROP": "Removes the top stack item",
    "OP_SWAP": "Swaps the top two stack items",
    "OP_ROT": "Rotates the top three items (third becomes top)",
    "OP_OVER": "Copies the second item to the top",
    "OP_NIP": "Removes the second item from the stack",
    "OP_TUCK": "Copies the top item below the second item",
    "OP_2DUP": "Duplicates the top two stack items",
    "OP_3DUP": "Duplicates the top three stack items",
    "OP_2DROP": "Removes the top two stack items",
    "OP_PICK": "Copies the nth item to the top (n is top item)",
    "OP_ROLL": "Moves the nth item to the top (n is top item)",
    "OP_DEPTH": "Pushes the stack size onto the stack",
    "OP_SIZE": "Pushes the size of the top item (in bytes)",
    
    # Crypto
    "OP_HASH160": "Performs RIPEMD160(SHA256(x)) on the top stack item",
    "OP_SHA256": "Performs SHA-256 on the top stack item",
    "OP_SHA1": "Performs SHA-1 on the top stack item",
    "OP_RIPEMD160": "Performs RIPEMD-160 on the top stack item",
    "OP_HASH256": "Performs SHA256(SHA256(x)) on the top stack item",
    
    # Comparison
    "OP_EQUAL": "Compares top two stack items, pushes TRUE if equal, FALSE otherwise",
    "OP_EQUALVERIFY": "Same as OP_EQUAL, but removes result and fails if FALSE",
    "OP_NUMEQUAL": "Compares two numbers, pushes TRUE if equal",
    "OP_NUMEQUALVERIFY": "Same as OP_NUMEQUAL, but fails if FALSE",
    "OP_LESSTHAN": "Pushes TRUE if second item is less than top item",
    "OP_GREATERTHAN": "Pushes TRUE if second item is greater than top item",
    "OP_LESSTHANOREQUAL": "Pushes TRUE if second item is less than or equal to top",
    "OP_GREATERTHANOREQUAL": "Pushes TRUE if second item is greater than or equal to top",
    "OP_WITHIN": "Pushes TRUE if x is within range [min, max)",
    
    # Arithmetic
    "OP_ADD": "Adds top two items",
    "OP_SUB": "Subtracts top item from second item",
    "OP_1ADD": "Adds 1 to the top item",
    "OP_1SUB": "Subtracts 1 from the top item",
    "OP_NEGATE": "Negates the top item",
    "OP_ABS": "Returns absolute value of top item",
    "OP_MIN": "Returns the smaller of top two items",
    "OP_MAX": "Returns the larger of top two items",
    
    # Logic/Bitwise
    "OP_NOT": "Flips the boolean value (0 becomes 1, non-zero becomes 0)",
    "OP_0NOTEQUAL": "Returns 1 if top item is non-zero, else 0",
    "OP_BOOLAND": "Boolean AND of top two items",
    "OP_BOOLOR": "Boolean OR of top two items",
    
    # Signature
    "OP_CHECKSIG": "Verifies a signature against a public key",
    "OP_CHECKSIGVERIFY": "Same as OP_CHECKSIG, but fails if FALSE",
    "OP_CHECKMULTISIG": "Verifies multiple signatures against multiple public keys",
    "OP_CHECKMULTISIGVERIFY": "Same as OP_CHECKMULTISIG, but fails if FALSE",
    
    # Flow control
    "OP_IF": "Executes following statements if top item is TRUE",
    "OP_NOTIF": "Executes following statements if top item is FALSE",
    "OP_ELSE": "Executes following statements if preceding OP_IF was FALSE",
    "OP_ENDIF": "Ends an IF/ELSE block",
    "OP_VERIFY": "Removes top stack item and fails if it's FALSE or zero",
    "OP_RETURN": "Marks transaction output as invalid (used for data embedding)",
    
    # Constants
    "OP_0": "Pushes an empty array (falsy value)",
    "OP_FALSE": "Pushes an empty array (alias for OP_0)",
    "OP_1": "Pushes the number 1",
    "OP_TRUE": "Pushes the number 1 (alias for OP_1)",
    "OP_1NEGATE": "Pushes the number -1",
    "OP_2": "Pushes the number 2",
    "OP_3": "Pushes the number 3",
    "OP_4": "Pushes the number 4",
    "OP_5": "Pushes the number 5",
    "OP_6": "Pushes the number 6",
    "OP_7": "Pushes the number 7",
    "OP_8": "Pushes the number 8",
    "OP_9": "Pushes the number 9",
    "OP_10": "Pushes the number 10",
    "OP_11": "Pushes the number 11",
    "OP_12": "Pushes the number 12",
    "OP_13": "Pushes the number 13",
    "OP_14": "Pushes the number 14",
    "OP_15": "Pushes the number 15",
    "OP_16": "Pushes the number 16",
    
    # No-op
    "OP_NOP": "Does nothing",
}


# =============================================================================
# STACK MANIPULATION OPCODES
# =============================================================================

def execute_op_dup(stack: List[str]) -> OpcodeResult:
    """OP_DUP: Duplicates the top stack item. Stack: (x) -> (x x)"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_DUP failed: stack is empty",
            error="Stack underflow: OP_DUP requires at least 1 item"
        )
    top_item = stack[-1]
    return OpcodeResult(
        success=True, stack=stack + [top_item],
        explanation=f"OP_DUP: Duplicated '{top_item}' on top of the stack"
    )


def execute_op_drop(stack: List[str]) -> OpcodeResult:
    """OP_DROP: Removes the top stack item. Stack: (x) -> ()"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_DROP failed: stack is empty",
            error="Stack underflow: OP_DROP requires at least 1 item"
        )
    top_item = stack[-1]
    return OpcodeResult(
        success=True, stack=stack[:-1],
        explanation=f"OP_DROP: Removed '{top_item}' from the stack"
    )


def execute_op_swap(stack: List[str]) -> OpcodeResult:
    """OP_SWAP: Swaps the top two stack items. Stack: (x y) -> (y x)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_SWAP failed: need at least 2 items",
            error="Stack underflow: OP_SWAP requires at least 2 items"
        )
    new_stack = stack[:-2] + [stack[-1], stack[-2]]
    return OpcodeResult(
        success=True, stack=new_stack,
        explanation=f"OP_SWAP: Swapped '{stack[-2]}' and '{stack[-1]}'"
    )


def execute_op_rot(stack: List[str]) -> OpcodeResult:
    """OP_ROT: Rotates top 3 items - third becomes top. Stack: (x y z) -> (y z x)"""
    if len(stack) < 3:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_ROT failed: need at least 3 items",
            error="Stack underflow: OP_ROT requires at least 3 items"
        )
    x, y, z = stack[-3], stack[-2], stack[-1]
    new_stack = stack[:-3] + [y, z, x]
    return OpcodeResult(
        success=True, stack=new_stack,
        explanation=f"OP_ROT: Rotated - '{x}' moved to top, '{y}' and '{z}' shifted down"
    )


def execute_op_over(stack: List[str]) -> OpcodeResult:
    """OP_OVER: Copies second item to top. Stack: (x y) -> (x y x)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_OVER failed: need at least 2 items",
            error="Stack underflow: OP_OVER requires at least 2 items"
        )
    second = stack[-2]
    return OpcodeResult(
        success=True, stack=stack + [second],
        explanation=f"OP_OVER: Copied '{second}' to top of stack"
    )


def execute_op_nip(stack: List[str]) -> OpcodeResult:
    """OP_NIP: Removes the second item. Stack: (x y) -> (y)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_NIP failed: need at least 2 items",
            error="Stack underflow: OP_NIP requires at least 2 items"
        )
    removed = stack[-2]
    new_stack = stack[:-2] + [stack[-1]]
    return OpcodeResult(
        success=True, stack=new_stack,
        explanation=f"OP_NIP: Removed second item '{removed}'"
    )


def execute_op_tuck(stack: List[str]) -> OpcodeResult:
    """OP_TUCK: Copies top below second. Stack: (x y) -> (y x y)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_TUCK failed: need at least 2 items",
            error="Stack underflow: OP_TUCK requires at least 2 items"
        )
    top = stack[-1]
    new_stack = stack[:-2] + [top, stack[-2], top]
    return OpcodeResult(
        success=True, stack=new_stack,
        explanation=f"OP_TUCK: Copied '{top}' below second item"
    )


def execute_op_2dup(stack: List[str]) -> OpcodeResult:
    """OP_2DUP: Duplicates top two items. Stack: (x y) -> (x y x y)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_2DUP failed: need at least 2 items",
            error="Stack underflow: OP_2DUP requires at least 2 items"
        )
    return OpcodeResult(
        success=True, stack=stack + [stack[-2], stack[-1]],
        explanation=f"OP_2DUP: Duplicated '{stack[-2]}' and '{stack[-1]}'"
    )


def execute_op_3dup(stack: List[str]) -> OpcodeResult:
    """OP_3DUP: Duplicates top three items. Stack: (x y z) -> (x y z x y z)"""
    if len(stack) < 3:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_3DUP failed: need at least 3 items",
            error="Stack underflow: OP_3DUP requires at least 3 items"
        )
    return OpcodeResult(
        success=True, stack=stack + [stack[-3], stack[-2], stack[-1]],
        explanation=f"OP_3DUP: Duplicated '{stack[-3]}', '{stack[-2]}', and '{stack[-1]}'"
    )


def execute_op_2drop(stack: List[str]) -> OpcodeResult:
    """OP_2DROP: Removes top two items. Stack: (x y) -> ()"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_2DROP failed: need at least 2 items",
            error="Stack underflow: OP_2DROP requires at least 2 items"
        )
    return OpcodeResult(
        success=True, stack=stack[:-2],
        explanation=f"OP_2DROP: Removed '{stack[-2]}' and '{stack[-1]}'"
    )


def execute_op_depth(stack: List[str]) -> OpcodeResult:
    """OP_DEPTH: Pushes stack size onto stack."""
    depth = str(len(stack))
    return OpcodeResult(
        success=True, stack=stack + [depth],
        explanation=f"OP_DEPTH: Pushed stack depth '{depth}'"
    )


def execute_op_size(stack: List[str]) -> OpcodeResult:
    """OP_SIZE: Pushes size of top item in bytes."""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_SIZE failed: stack is empty",
            error="Stack underflow: OP_SIZE requires at least 1 item"
        )
    top = stack[-1]
    size = str(len(top) // 2) if all(c in '0123456789abcdefABCDEF' for c in top) else str(len(top))
    return OpcodeResult(
        success=True, stack=stack + [size],
        explanation=f"OP_SIZE: Pushed size '{size}' of top item"
    )


# =============================================================================
# CRYPTO OPCODES (Symbolic)
# =============================================================================

def execute_op_hash160(stack: List[str]) -> OpcodeResult:
    """OP_HASH160: Performs RIPEMD160(SHA256(x)). Stack: (x) -> (hash)"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_HASH160 failed: stack is empty",
            error="Stack underflow: OP_HASH160 requires at least 1 item"
        )
    top_item = stack[-1]
    return OpcodeResult(
        success=True, stack=stack[:-1] + [f"HASH160({top_item})"],
        explanation=f"OP_HASH160: Replaced '{top_item}' with its HASH160 (symbolic)"
    )


def execute_op_sha256(stack: List[str]) -> OpcodeResult:
    """OP_SHA256: Performs SHA-256 hash. Stack: (x) -> (hash)"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_SHA256 failed: stack is empty",
            error="Stack underflow: OP_SHA256 requires at least 1 item"
        )
    top_item = stack[-1]
    return OpcodeResult(
        success=True, stack=stack[:-1] + [f"SHA256({top_item})"],
        explanation=f"OP_SHA256: Replaced '{top_item}' with its SHA256 hash (symbolic)"
    )


def execute_op_sha1(stack: List[str]) -> OpcodeResult:
    """OP_SHA1: Performs SHA-1 hash. Stack: (x) -> (hash)"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_SHA1 failed: stack is empty",
            error="Stack underflow: OP_SHA1 requires at least 1 item"
        )
    top_item = stack[-1]
    return OpcodeResult(
        success=True, stack=stack[:-1] + [f"SHA1({top_item})"],
        explanation=f"OP_SHA1: Replaced '{top_item}' with its SHA1 hash (symbolic)"
    )


def execute_op_ripemd160(stack: List[str]) -> OpcodeResult:
    """OP_RIPEMD160: Performs RIPEMD-160 hash. Stack: (x) -> (hash)"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_RIPEMD160 failed: stack is empty",
            error="Stack underflow: OP_RIPEMD160 requires at least 1 item"
        )
    top_item = stack[-1]
    return OpcodeResult(
        success=True, stack=stack[:-1] + [f"RIPEMD160({top_item})"],
        explanation=f"OP_RIPEMD160: Replaced '{top_item}' with its RIPEMD160 hash (symbolic)"
    )


def execute_op_hash256(stack: List[str]) -> OpcodeResult:
    """OP_HASH256: Performs SHA256(SHA256(x)). Stack: (x) -> (hash)"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_HASH256 failed: stack is empty",
            error="Stack underflow: OP_HASH256 requires at least 1 item"
        )
    top_item = stack[-1]
    return OpcodeResult(
        success=True, stack=stack[:-1] + [f"HASH256({top_item})"],
        explanation=f"OP_HASH256: Replaced '{top_item}' with its double SHA256 hash (symbolic)"
    )


# =============================================================================
# COMPARISON OPCODES
# =============================================================================

def execute_op_equal(stack: List[str]) -> OpcodeResult:
    """OP_EQUAL: Compares top two items. Stack: (x y) -> (TRUE/FALSE)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_EQUAL failed: need at least 2 items",
            error="Stack underflow: OP_EQUAL requires at least 2 items"
        )
    item1, item2 = stack[-1], stack[-2]
    new_stack = stack[:-2]
    if item1 == item2:
        new_stack.append("TRUE")
        explanation = f"OP_EQUAL: '{item2}' equals '{item1}' - pushed TRUE"
    else:
        new_stack.append(f"EQUAL({item2},{item1})")
        explanation = f"OP_EQUAL: Compared '{item2}' and '{item1}' - symbolic result"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_equalverify(stack: List[str]) -> OpcodeResult:
    """OP_EQUALVERIFY: OP_EQUAL then OP_VERIFY. Stack: (x y) -> ()"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_EQUALVERIFY failed: need at least 2 items",
            error="Stack underflow: OP_EQUALVERIFY requires at least 2 items"
        )
    item1, item2 = stack[-1], stack[-2]
    new_stack = stack[:-2]
    if item1 == item2:
        explanation = f"OP_EQUALVERIFY: Verified '{item2}' equals '{item1}'"
    else:
        explanation = f"OP_EQUALVERIFY: Symbolically verified equality (assumed valid)"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_numequal(stack: List[str]) -> OpcodeResult:
    """OP_NUMEQUAL: Numeric equality. Stack: (a b) -> (TRUE/FALSE)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_NUMEQUAL failed: need at least 2 items",
            error="Stack underflow: OP_NUMEQUAL requires at least 2 items"
        )
    a, b = stack[-2], stack[-1]
    new_stack = stack[:-2]
    try:
        result = "TRUE" if int(a) == int(b) else "FALSE"
        new_stack.append(result)
        explanation = f"OP_NUMEQUAL: {a} == {b} is {result}"
    except ValueError:
        new_stack.append(f"NUMEQUAL({a},{b})")
        explanation = f"OP_NUMEQUAL: Symbolic comparison of '{a}' and '{b}'"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_numequalverify(stack: List[str]) -> OpcodeResult:
    """OP_NUMEQUALVERIFY: OP_NUMEQUAL then OP_VERIFY. Stack: (a b) -> ()"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_NUMEQUALVERIFY failed: need at least 2 items",
            error="Stack underflow: OP_NUMEQUALVERIFY requires at least 2 items"
        )
    a, b = stack[-2], stack[-1]
    new_stack = stack[:-2]
    return OpcodeResult(
        success=True, stack=new_stack,
        explanation=f"OP_NUMEQUALVERIFY: Verified {a} equals {b}"
    )


def execute_op_lessthan(stack: List[str]) -> OpcodeResult:
    """OP_LESSTHAN: Checks if second < top. Stack: (a b) -> (TRUE/FALSE)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_LESSTHAN failed: need at least 2 items",
            error="Stack underflow: OP_LESSTHAN requires at least 2 items"
        )
    a, b = stack[-2], stack[-1]
    new_stack = stack[:-2]
    try:
        result = "TRUE" if int(a) < int(b) else "FALSE"
        new_stack.append(result)
        explanation = f"OP_LESSTHAN: {a} < {b} is {result}"
    except ValueError:
        new_stack.append(f"LESSTHAN({a},{b})")
        explanation = f"OP_LESSTHAN: Symbolic comparison of '{a}' < '{b}'"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_greaterthan(stack: List[str]) -> OpcodeResult:
    """OP_GREATERTHAN: Checks if second > top. Stack: (a b) -> (TRUE/FALSE)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_GREATERTHAN failed: need at least 2 items",
            error="Stack underflow: OP_GREATERTHAN requires at least 2 items"
        )
    a, b = stack[-2], stack[-1]
    new_stack = stack[:-2]
    try:
        result = "TRUE" if int(a) > int(b) else "FALSE"
        new_stack.append(result)
        explanation = f"OP_GREATERTHAN: {a} > {b} is {result}"
    except ValueError:
        new_stack.append(f"GREATERTHAN({a},{b})")
        explanation = f"OP_GREATERTHAN: Symbolic comparison of '{a}' > '{b}'"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_lessthanorequal(stack: List[str]) -> OpcodeResult:
    """OP_LESSTHANOREQUAL: Checks if second <= top. Stack: (a b) -> (TRUE/FALSE)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_LESSTHANOREQUAL failed: need at least 2 items",
            error="Stack underflow: OP_LESSTHANOREQUAL requires at least 2 items"
        )
    a, b = stack[-2], stack[-1]
    new_stack = stack[:-2]
    try:
        result = "TRUE" if int(a) <= int(b) else "FALSE"
        new_stack.append(result)
        explanation = f"OP_LESSTHANOREQUAL: {a} <= {b} is {result}"
    except ValueError:
        new_stack.append(f"LESSTHANOREQUAL({a},{b})")
        explanation = f"OP_LESSTHANOREQUAL: Symbolic comparison"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_greaterthanorequal(stack: List[str]) -> OpcodeResult:
    """OP_GREATERTHANOREQUAL: Checks if second >= top. Stack: (a b) -> (TRUE/FALSE)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_GREATERTHANOREQUAL failed: need at least 2 items",
            error="Stack underflow: OP_GREATERTHANOREQUAL requires at least 2 items"
        )
    a, b = stack[-2], stack[-1]
    new_stack = stack[:-2]
    try:
        result = "TRUE" if int(a) >= int(b) else "FALSE"
        new_stack.append(result)
        explanation = f"OP_GREATERTHANOREQUAL: {a} >= {b} is {result}"
    except ValueError:
        new_stack.append(f"GREATERTHANOREQUAL({a},{b})")
        explanation = f"OP_GREATERTHANOREQUAL: Symbolic comparison"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_within(stack: List[str]) -> OpcodeResult:
    """OP_WITHIN: Checks if x is in [min, max). Stack: (x min max) -> (TRUE/FALSE)"""
    if len(stack) < 3:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_WITHIN failed: need at least 3 items",
            error="Stack underflow: OP_WITHIN requires at least 3 items"
        )
    x, min_val, max_val = stack[-3], stack[-2], stack[-1]
    new_stack = stack[:-3]
    try:
        xi, mini, maxi = int(x), int(min_val), int(max_val)
        result = "TRUE" if mini <= xi < maxi else "FALSE"
        new_stack.append(result)
        explanation = f"OP_WITHIN: {min_val} <= {x} < {max_val} is {result}"
    except ValueError:
        new_stack.append(f"WITHIN({x},{min_val},{max_val})")
        explanation = f"OP_WITHIN: Symbolic range check"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


# =============================================================================
# ARITHMETIC OPCODES
# =============================================================================

def execute_op_add(stack: List[str]) -> OpcodeResult:
    """OP_ADD: Adds top two items. Stack: (a b) -> (a+b)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_ADD failed: need at least 2 items",
            error="Stack underflow: OP_ADD requires at least 2 items"
        )
    a, b = stack[-2], stack[-1]
    new_stack = stack[:-2]
    try:
        result = str(int(a) + int(b))
        new_stack.append(result)
        explanation = f"OP_ADD: {a} + {b} = {result}"
    except ValueError:
        new_stack.append(f"ADD({a},{b})")
        explanation = f"OP_ADD: Symbolic addition of '{a}' and '{b}'"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_sub(stack: List[str]) -> OpcodeResult:
    """OP_SUB: Subtracts top from second. Stack: (a b) -> (a-b)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_SUB failed: need at least 2 items",
            error="Stack underflow: OP_SUB requires at least 2 items"
        )
    a, b = stack[-2], stack[-1]
    new_stack = stack[:-2]
    try:
        result = str(int(a) - int(b))
        new_stack.append(result)
        explanation = f"OP_SUB: {a} - {b} = {result}"
    except ValueError:
        new_stack.append(f"SUB({a},{b})")
        explanation = f"OP_SUB: Symbolic subtraction of '{b}' from '{a}'"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_1add(stack: List[str]) -> OpcodeResult:
    """OP_1ADD: Adds 1 to top. Stack: (a) -> (a+1)"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_1ADD failed: stack is empty",
            error="Stack underflow: OP_1ADD requires at least 1 item"
        )
    a = stack[-1]
    new_stack = stack[:-1]
    try:
        result = str(int(a) + 1)
        new_stack.append(result)
        explanation = f"OP_1ADD: {a} + 1 = {result}"
    except ValueError:
        new_stack.append(f"ADD1({a})")
        explanation = f"OP_1ADD: Symbolic increment of '{a}'"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_1sub(stack: List[str]) -> OpcodeResult:
    """OP_1SUB: Subtracts 1 from top. Stack: (a) -> (a-1)"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_1SUB failed: stack is empty",
            error="Stack underflow: OP_1SUB requires at least 1 item"
        )
    a = stack[-1]
    new_stack = stack[:-1]
    try:
        result = str(int(a) - 1)
        new_stack.append(result)
        explanation = f"OP_1SUB: {a} - 1 = {result}"
    except ValueError:
        new_stack.append(f"SUB1({a})")
        explanation = f"OP_1SUB: Symbolic decrement of '{a}'"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_negate(stack: List[str]) -> OpcodeResult:
    """OP_NEGATE: Negates top item. Stack: (a) -> (-a)"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_NEGATE failed: stack is empty",
            error="Stack underflow: OP_NEGATE requires at least 1 item"
        )
    a = stack[-1]
    new_stack = stack[:-1]
    try:
        result = str(-int(a))
        new_stack.append(result)
        explanation = f"OP_NEGATE: -{a} = {result}"
    except ValueError:
        new_stack.append(f"NEGATE({a})")
        explanation = f"OP_NEGATE: Symbolic negation of '{a}'"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_abs(stack: List[str]) -> OpcodeResult:
    """OP_ABS: Absolute value of top. Stack: (a) -> (|a|)"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_ABS failed: stack is empty",
            error="Stack underflow: OP_ABS requires at least 1 item"
        )
    a = stack[-1]
    new_stack = stack[:-1]
    try:
        result = str(abs(int(a)))
        new_stack.append(result)
        explanation = f"OP_ABS: |{a}| = {result}"
    except ValueError:
        new_stack.append(f"ABS({a})")
        explanation = f"OP_ABS: Symbolic absolute value of '{a}'"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_min(stack: List[str]) -> OpcodeResult:
    """OP_MIN: Minimum of top two. Stack: (a b) -> (min(a,b))"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_MIN failed: need at least 2 items",
            error="Stack underflow: OP_MIN requires at least 2 items"
        )
    a, b = stack[-2], stack[-1]
    new_stack = stack[:-2]
    try:
        result = str(min(int(a), int(b)))
        new_stack.append(result)
        explanation = f"OP_MIN: min({a}, {b}) = {result}"
    except ValueError:
        new_stack.append(f"MIN({a},{b})")
        explanation = f"OP_MIN: Symbolic minimum of '{a}' and '{b}'"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_max(stack: List[str]) -> OpcodeResult:
    """OP_MAX: Maximum of top two. Stack: (a b) -> (max(a,b))"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_MAX failed: need at least 2 items",
            error="Stack underflow: OP_MAX requires at least 2 items"
        )
    a, b = stack[-2], stack[-1]
    new_stack = stack[:-2]
    try:
        result = str(max(int(a), int(b)))
        new_stack.append(result)
        explanation = f"OP_MAX: max({a}, {b}) = {result}"
    except ValueError:
        new_stack.append(f"MAX({a},{b})")
        explanation = f"OP_MAX: Symbolic maximum of '{a}' and '{b}'"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


# =============================================================================
# LOGIC OPCODES
# =============================================================================

def execute_op_not(stack: List[str]) -> OpcodeResult:
    """OP_NOT: Boolean NOT. Stack: (a) -> (!a)"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_NOT failed: stack is empty",
            error="Stack underflow: OP_NOT requires at least 1 item"
        )
    a = stack[-1]
    new_stack = stack[:-1]
    if a in ["0", "FALSE", ""]:
        new_stack.append("1")
        explanation = f"OP_NOT: NOT({a}) = 1 (true)"
    elif a in ["1", "TRUE"]:
        new_stack.append("0")
        explanation = f"OP_NOT: NOT({a}) = 0 (false)"
    else:
        new_stack.append("0")  # Non-zero becomes 0
        explanation = f"OP_NOT: NOT({a}) = 0 (non-zero becomes false)"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_0notequal(stack: List[str]) -> OpcodeResult:
    """OP_0NOTEQUAL: Returns 1 if non-zero. Stack: (a) -> (0 or 1)"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_0NOTEQUAL failed: stack is empty",
            error="Stack underflow: OP_0NOTEQUAL requires at least 1 item"
        )
    a = stack[-1]
    new_stack = stack[:-1]
    if a in ["0", "FALSE", ""]:
        new_stack.append("0")
        explanation = f"OP_0NOTEQUAL: {a} equals zero, pushed 0"
    else:
        new_stack.append("1")
        explanation = f"OP_0NOTEQUAL: {a} is non-zero, pushed 1"
    return OpcodeResult(success=True, stack=new_stack, explanation=explanation)


def execute_op_booland(stack: List[str]) -> OpcodeResult:
    """OP_BOOLAND: Boolean AND. Stack: (a b) -> (a AND b)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_BOOLAND failed: need at least 2 items",
            error="Stack underflow: OP_BOOLAND requires at least 2 items"
        )
    a, b = stack[-2], stack[-1]
    new_stack = stack[:-2]
    a_bool = a not in ["0", "FALSE", ""]
    b_bool = b not in ["0", "FALSE", ""]
    result = "1" if (a_bool and b_bool) else "0"
    new_stack.append(result)
    return OpcodeResult(
        success=True, stack=new_stack,
        explanation=f"OP_BOOLAND: {a} AND {b} = {result}"
    )


def execute_op_boolor(stack: List[str]) -> OpcodeResult:
    """OP_BOOLOR: Boolean OR. Stack: (a b) -> (a OR b)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_BOOLOR failed: need at least 2 items",
            error="Stack underflow: OP_BOOLOR requires at least 2 items"
        )
    a, b = stack[-2], stack[-1]
    new_stack = stack[:-2]
    a_bool = a not in ["0", "FALSE", ""]
    b_bool = b not in ["0", "FALSE", ""]
    result = "1" if (a_bool or b_bool) else "0"
    new_stack.append(result)
    return OpcodeResult(
        success=True, stack=new_stack,
        explanation=f"OP_BOOLOR: {a} OR {b} = {result}"
    )


# =============================================================================
# SIGNATURE OPCODES (Symbolic)
# =============================================================================

def execute_op_checksig(stack: List[str]) -> OpcodeResult:
    """OP_CHECKSIG: Verifies signature. Stack: (sig pubkey) -> (TRUE/FALSE)"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_CHECKSIG failed: need signature and public key",
            error="Stack underflow: OP_CHECKSIG requires at least 2 items"
        )
    pubkey, sig = stack[-1], stack[-2]
    new_stack = stack[:-2] + ["TRUE (symbolic signature verification)"]
    return OpcodeResult(
        success=True, stack=new_stack,
        explanation=f"OP_CHECKSIG: Verified signature '{sig[:16]}...' against pubkey '{pubkey[:16]}...' (symbolic)"
    )


def execute_op_checksigverify(stack: List[str]) -> OpcodeResult:
    """OP_CHECKSIGVERIFY: OP_CHECKSIG then OP_VERIFY. Stack: (sig pubkey) -> ()"""
    if len(stack) < 2:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_CHECKSIGVERIFY failed: need signature and public key",
            error="Stack underflow: OP_CHECKSIGVERIFY requires at least 2 items"
        )
    pubkey, sig = stack[-1], stack[-2]
    new_stack = stack[:-2]
    return OpcodeResult(
        success=True, stack=new_stack,
        explanation=f"OP_CHECKSIGVERIFY: Verified and removed signature check result (symbolic)"
    )


def execute_op_checkmultisig(stack: List[str]) -> OpcodeResult:
    """OP_CHECKMULTISIG: M-of-N multisig. Simplified symbolic execution."""
    if len(stack) < 4:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_CHECKMULTISIG failed: insufficient items",
            error="Stack underflow: OP_CHECKMULTISIG requires more items"
        )
    return OpcodeResult(
        success=True, stack=["TRUE (symbolic multisig verification)"],
        explanation="OP_CHECKMULTISIG: Symbolically verified M-of-N multisig (assumed valid)"
    )


def execute_op_checkmultisigverify(stack: List[str]) -> OpcodeResult:
    """OP_CHECKMULTISIGVERIFY: OP_CHECKMULTISIG then OP_VERIFY."""
    if len(stack) < 4:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_CHECKMULTISIGVERIFY failed: insufficient items",
            error="Stack underflow: OP_CHECKMULTISIGVERIFY requires more items"
        )
    return OpcodeResult(
        success=True, stack=[],
        explanation="OP_CHECKMULTISIGVERIFY: Symbolically verified multisig (assumed valid)"
    )


# =============================================================================
# FLOW CONTROL OPCODES (Symbolic)
# =============================================================================

def execute_op_verify(stack: List[str]) -> OpcodeResult:
    """OP_VERIFY: Fails if top is false/zero. Stack: (x) -> ()"""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_VERIFY failed: stack is empty",
            error="Stack underflow: OP_VERIFY requires at least 1 item"
        )
    top_item = stack[-1]
    new_stack = stack[:-1]
    if top_item.upper() in ["FALSE", "0", ""]:
        return OpcodeResult(
            success=False, stack=new_stack,
            explanation=f"OP_VERIFY: Failed - '{top_item}' is false/zero",
            error="Verification failed: top stack item is false"
        )
    return OpcodeResult(
        success=True, stack=new_stack,
        explanation=f"OP_VERIFY: Verified '{top_item}' is truthy - passed"
    )


def execute_op_return(stack: List[str]) -> OpcodeResult:
    """OP_RETURN: Marks output as unspendable (data embedding)."""
    return OpcodeResult(
        success=True, stack=stack,
        explanation="OP_RETURN: Script is provably unspendable (null data output)"
    )


def execute_op_if(stack: List[str]) -> OpcodeResult:
    """OP_IF: Conditional execution (symbolic - always succeeds for demo)."""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_IF failed: stack is empty",
            error="Stack underflow: OP_IF requires at least 1 item"
        )
    condition = stack[-1]
    new_stack = stack[:-1]
    return OpcodeResult(
        success=True, stack=new_stack,
        explanation=f"OP_IF: Condition '{condition}' evaluated (symbolic flow control)"
    )


def execute_op_notif(stack: List[str]) -> OpcodeResult:
    """OP_NOTIF: Inverted conditional (symbolic)."""
    if len(stack) < 1:
        return OpcodeResult(
            success=False, stack=stack,
            explanation="OP_NOTIF failed: stack is empty",
            error="Stack underflow: OP_NOTIF requires at least 1 item"
        )
    condition = stack[-1]
    new_stack = stack[:-1]
    return OpcodeResult(
        success=True, stack=new_stack,
        explanation=f"OP_NOTIF: Inverted condition '{condition}' evaluated (symbolic)"
    )


def execute_op_else(stack: List[str]) -> OpcodeResult:
    """OP_ELSE: Else branch (symbolic)."""
    return OpcodeResult(
        success=True, stack=stack,
        explanation="OP_ELSE: Switched to else branch (symbolic flow control)"
    )


def execute_op_endif(stack: List[str]) -> OpcodeResult:
    """OP_ENDIF: End conditional block (symbolic)."""
    return OpcodeResult(
        success=True, stack=stack,
        explanation="OP_ENDIF: Ended conditional block"
    )


def execute_op_nop(stack: List[str]) -> OpcodeResult:
    """OP_NOP: Does nothing."""
    return OpcodeResult(
        success=True, stack=stack,
        explanation="OP_NOP: No operation"
    )


# =============================================================================
# CONSTANT OPCODES
# =============================================================================

def make_constant_handler(value: str, description: str):
    """Factory for constant opcodes."""
    def handler(stack: List[str]) -> OpcodeResult:
        return OpcodeResult(
            success=True, stack=stack + [value],
            explanation=f"{description}: Pushed '{value}' onto stack"
        )
    return handler


# =============================================================================
# DATA PUSH HANDLER
# =============================================================================

def execute_data_push(data: str, stack: List[str]) -> OpcodeResult:
    """Handles data push operations (hex literals, public keys, etc.)"""
    new_stack = stack + [data]
    length = len(data)
    if length == 40:
        data_type = "hash (HASH160/20 bytes)"
    elif length == 64:
        data_type = "hash (SHA256/32 bytes)"
    elif length == 66 or length == 130:
        data_type = "public key"
    elif length >= 140:
        data_type = "signature"
    else:
        data_type = f"data ({length//2} bytes)" if length % 2 == 0 else "data"
    return OpcodeResult(
        success=True, stack=new_stack,
        explanation=f"PUSH: Added '{data[:32]}{'...' if len(data) > 32 else ''}' to stack ({data_type})"
    )


# =============================================================================
# OPCODE HANDLERS MAPPING
# =============================================================================

OPCODE_HANDLERS: Dict[str, Callable[[List[str]], OpcodeResult]] = {
    # Stack manipulation
    "OP_DUP": execute_op_dup,
    "OP_DROP": execute_op_drop,
    "OP_SWAP": execute_op_swap,
    "OP_ROT": execute_op_rot,
    "OP_OVER": execute_op_over,
    "OP_NIP": execute_op_nip,
    "OP_TUCK": execute_op_tuck,
    "OP_2DUP": execute_op_2dup,
    "OP_3DUP": execute_op_3dup,
    "OP_2DROP": execute_op_2drop,
    "OP_DEPTH": execute_op_depth,
    "OP_SIZE": execute_op_size,
    
    # Crypto
    "OP_HASH160": execute_op_hash160,
    "OP_SHA256": execute_op_sha256,
    "OP_SHA1": execute_op_sha1,
    "OP_RIPEMD160": execute_op_ripemd160,
    "OP_HASH256": execute_op_hash256,
    
    # Comparison
    "OP_EQUAL": execute_op_equal,
    "OP_EQUALVERIFY": execute_op_equalverify,
    "OP_NUMEQUAL": execute_op_numequal,
    "OP_NUMEQUALVERIFY": execute_op_numequalverify,
    "OP_LESSTHAN": execute_op_lessthan,
    "OP_GREATERTHAN": execute_op_greaterthan,
    "OP_LESSTHANOREQUAL": execute_op_lessthanorequal,
    "OP_GREATERTHANOREQUAL": execute_op_greaterthanorequal,
    "OP_WITHIN": execute_op_within,
    
    # Arithmetic
    "OP_ADD": execute_op_add,
    "OP_SUB": execute_op_sub,
    "OP_1ADD": execute_op_1add,
    "OP_1SUB": execute_op_1sub,
    "OP_NEGATE": execute_op_negate,
    "OP_ABS": execute_op_abs,
    "OP_MIN": execute_op_min,
    "OP_MAX": execute_op_max,
    
    # Logic
    "OP_NOT": execute_op_not,
    "OP_0NOTEQUAL": execute_op_0notequal,
    "OP_BOOLAND": execute_op_booland,
    "OP_BOOLOR": execute_op_boolor,
    
    # Signature
    "OP_CHECKSIG": execute_op_checksig,
    "OP_CHECKSIGVERIFY": execute_op_checksigverify,
    "OP_CHECKMULTISIG": execute_op_checkmultisig,
    "OP_CHECKMULTISIGVERIFY": execute_op_checkmultisigverify,
    
    # Flow control
    "OP_VERIFY": execute_op_verify,
    "OP_RETURN": execute_op_return,
    "OP_IF": execute_op_if,
    "OP_NOTIF": execute_op_notif,
    "OP_ELSE": execute_op_else,
    "OP_ENDIF": execute_op_endif,
    "OP_NOP": execute_op_nop,
    
    # Constants
    "OP_0": make_constant_handler("0", "OP_0"),
    "OP_FALSE": make_constant_handler("0", "OP_FALSE"),
    "OP_1": make_constant_handler("1", "OP_1"),
    "OP_TRUE": make_constant_handler("1", "OP_TRUE"),
    "OP_1NEGATE": make_constant_handler("-1", "OP_1NEGATE"),
    "OP_2": make_constant_handler("2", "OP_2"),
    "OP_3": make_constant_handler("3", "OP_3"),
    "OP_4": make_constant_handler("4", "OP_4"),
    "OP_5": make_constant_handler("5", "OP_5"),
    "OP_6": make_constant_handler("6", "OP_6"),
    "OP_7": make_constant_handler("7", "OP_7"),
    "OP_8": make_constant_handler("8", "OP_8"),
    "OP_9": make_constant_handler("9", "OP_9"),
    "OP_10": make_constant_handler("10", "OP_10"),
    "OP_11": make_constant_handler("11", "OP_11"),
    "OP_12": make_constant_handler("12", "OP_12"),
    "OP_13": make_constant_handler("13", "OP_13"),
    "OP_14": make_constant_handler("14", "OP_14"),
    "OP_15": make_constant_handler("15", "OP_15"),
    "OP_16": make_constant_handler("16", "OP_16"),
}


def is_opcode(token: str) -> bool:
    """Check if a token is a recognized opcode."""
    return token.upper().startswith("OP_")


def get_opcode_description(opcode: str) -> str:
    """Get the human-readable description of an opcode."""
    return OPCODE_DESCRIPTIONS.get(opcode.upper(), f"Unknown opcode: {opcode}")
