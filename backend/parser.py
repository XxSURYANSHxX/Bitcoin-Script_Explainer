"""
Bitcoin Script parser for ASM format.

This module parses Bitcoin Script in ASM (assembly) format into tokens
that can be processed by the explainer.
"""

from typing import List, Tuple
import re


class ParseError(Exception):
    """Raised when script parsing fails."""
    pass


def tokenize_script(script: str) -> List[str]:
    """
    Tokenize a Bitcoin Script in ASM format.
    
    Args:
        script: Bitcoin Script in ASM format (space-separated opcodes and data)
        
    Returns:
        List of tokens (opcodes and data pushes)
        
    Raises:
        ParseError: If the script is malformed
        
    Example:
        >>> tokenize_script("OP_DUP OP_HASH160 ab6807 OP_EQUALVERIFY OP_CHECKSIG")
        ['OP_DUP', 'OP_HASH160', 'ab6807', 'OP_EQUALVERIFY', 'OP_CHECKSIG']
    """
    if not script or not script.strip():
        raise ParseError("Empty script provided")
    
    # Normalize whitespace - handle multiple spaces, tabs, newlines
    normalized = re.sub(r'\s+', ' ', script.strip())
    
    # Split on whitespace
    tokens = normalized.split(' ')
    
    # Filter out empty tokens
    tokens = [t for t in tokens if t]
    
    if not tokens:
        raise ParseError("Script contains no valid tokens")
    
    # Validate each token
    validated_tokens = []
    for token in tokens:
        validated = validate_token(token)
        validated_tokens.append(validated)
    
    return validated_tokens


def validate_token(token: str) -> str:
    """
    Validate and normalize a single token.
    
    Args:
        token: A single token from the script
        
    Returns:
        Normalized token (opcodes uppercased)
        
    Raises:
        ParseError: If the token is invalid
    """
    token = token.strip()
    
    if not token:
        raise ParseError("Empty token encountered")
    
    # Check if it's an opcode (starts with OP_)
    if token.upper().startswith("OP_"):
        return token.upper()
    
    # Check if it's a valid hex string (data push)
    if is_valid_hex(token):
        return token.lower()  # Normalize hex to lowercase
    
    # Check if it's a number (for stack operations)
    if token.isdigit():
        return token
    
    # Could be a label or identifier - allow it but warn
    # This is lenient parsing for educational purposes
    if re.match(r'^[a-zA-Z0-9_<>]+$', token):
        return token
    
    raise ParseError(f"Invalid token: '{token}' - must be opcode (OP_*) or hex data")


def is_valid_hex(s: str) -> bool:
    """
    Check if a string is a valid hexadecimal value.
    
    Args:
        s: String to check
        
    Returns:
        True if valid hex, False otherwise
    """
    if not s:
        return False
    
    # Remove optional 0x prefix
    if s.lower().startswith('0x'):
        s = s[2:]
    
    # Check if all characters are valid hex digits
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def parse_script(script: str) -> Tuple[List[str], str]:
    """
    Parse a Bitcoin Script and return tokens with any warnings.
    
    Args:
        script: Bitcoin Script in ASM format
        
    Returns:
        Tuple of (tokens, warning_message)
        warning_message is empty if no warnings
    """
    tokens = tokenize_script(script)
    warnings = []
    
    # Check for potential issues
    if len(tokens) == 1 and tokens[0].upper() == "OP_RETURN":
        warnings.append("Script contains only OP_RETURN with no data payload")
    
    # Check for unrecognized opcodes
    known_opcodes = {
        "OP_DUP", "OP_HASH160", "OP_EQUAL", "OP_EQUALVERIFY",
        "OP_CHECKSIG", "OP_CHECKMULTISIG", "OP_VERIFY", "OP_RETURN"
    }
    
    for token in tokens:
        if token.upper().startswith("OP_") and token.upper() not in known_opcodes:
            warnings.append(f"Unknown opcode '{token}' - will be processed as no-op")
    
    warning_message = "; ".join(warnings) if warnings else ""
    
    return tokens, warning_message


def get_script_components(tokens: List[str]) -> dict:
    """
    Analyze script tokens and categorize them.
    
    Args:
        tokens: List of script tokens
        
    Returns:
        Dictionary with categorized components
    """
    components = {
        "opcodes": [],
        "data_pushes": [],
        "total_tokens": len(tokens)
    }
    
    for token in tokens:
        if token.upper().startswith("OP_"):
            components["opcodes"].append(token.upper())
        else:
            components["data_pushes"].append(token)
    
    return components
