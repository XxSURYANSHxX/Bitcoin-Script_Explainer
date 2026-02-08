"""
Core Bitcoin Script explainer module.

This module orchestrates the parsing, execution, and explanation of Bitcoin Scripts.
It provides a step-by-step breakdown of script execution with symbolic values.

IMPORTANT DISCLAIMER:
This is an educational tool and NOT a consensus-level Bitcoin Script validator.
It uses symbolic execution and does not perform real cryptographic operations.
"""

from typing import List, Tuple, Optional
from .parser import parse_script, ParseError
from .detector import detect_script_type
from .opcodes import (
    OPCODE_HANDLERS,
    execute_data_push,
    is_opcode,
    get_opcode_description,
    OpcodeResult
)
from .models import StackState, ScriptExplanation


class Explainer:
    """
    Bitcoin Script explainer that provides step-by-step execution analysis.
    """
    
    def __init__(self):
        self.stack: List[str] = []
        self.steps: List[StackState] = []
        self.errors: List[str] = []
    
    def reset(self):
        """Reset the explainer state for a new script."""
        self.stack = []
        self.steps = []
        self.errors = []
    
    def explain(self, script: str) -> ScriptExplanation:
        """
        Fully explain a Bitcoin Script.
        
        Args:
            script: Bitcoin Script in ASM format
            
        Returns:
            ScriptExplanation with complete breakdown
        """
        self.reset()
        self.warnings = []  # Track warnings for forgiving execution
        
        # Parse the script
        try:
            tokens, parse_warning = parse_script(script)
        except ParseError as e:
            return ScriptExplanation(
                script=script,
                script_type="Error",
                steps=[],
                summary=f"Failed to parse script: {str(e)}",
                success=False,
                error=str(e)
            )
        
        # Detect script type FIRST (before execution)
        script_type, type_description = detect_script_type(tokens)
        
        # Check if this is an Unknown/Custom script (forgiving mode)
        from .detector import UNKNOWN
        is_forgiving_mode = (script_type == UNKNOWN)
        
        # Preload symbolic stack based on script type
        initial_stack = self._get_symbolic_initial_stack(script_type, tokens)
        self.stack = initial_stack.copy()
        initial_stack_message = self._get_initial_stack_message(script_type, initial_stack)
        
        # Execute each token
        success = True
        error_message = None
        
        for i, token in enumerate(tokens):
            stack_before = self.stack.copy()
            
            try:
                result = self._execute_token(token)
                
                # FORGIVING EXECUTION: If failed and in forgiving mode, try recovery
                if not result.success and is_forgiving_mode:
                    result, recovery_warning = self._forgiving_execute(token, result)
                    if recovery_warning:
                        self.warnings.append(recovery_warning)
                
                step = StackState(
                    step=i,
                    opcode=token,
                    stack_before=stack_before,
                    stack_after=result.stack.copy(),
                    explanation=result.explanation
                )
                self.steps.append(step)
                
                if not result.success:
                    success = False
                    error_message = result.error
                    break
                    
            except Exception as e:
                success = False
                error_message = f"Execution error at step {i} ({token}): {str(e)}"
                
                step = StackState(
                    step=i,
                    opcode=token,
                    stack_before=stack_before,
                    stack_after=self.stack.copy(),
                    explanation=f"Error: {str(e)}"
                )
                self.steps.append(step)
                break
        
        # Generate summary
        summary = self._generate_summary(
            script=script,
            script_type=script_type,
            type_description=type_description,
            success=success,
            parse_warning=parse_warning,
            initial_stack_message=initial_stack_message,
            warnings=self.warnings
        )
        
        return ScriptExplanation(
            script=script,
            script_type=script_type,
            steps=self.steps,
            summary=summary,
            success=success,
            error=error_message
        )
    
    def _forgiving_execute(self, token: str, failed_result: OpcodeResult) -> tuple:
        """
        Attempt forgiving execution for Unknown/Custom scripts.
        
        When an opcode fails due to stack underflow, inject symbolic data
        and retry. Returns (new_result, warning_message).
        """
        from .opcodes import OpcodeResult, OPCODE_HANDLERS
        token_upper = token.upper()
        warning = None
        
        # OP_DUP on empty stack
        if token_upper == "OP_DUP" and len(self.stack) < 1:
            self.stack.append("<symbolic_input>")
            warning = "Symbolic input injected for OP_DUP (empty stack)."
            result = OPCODE_HANDLERS[token_upper](self.stack)
            self.stack = result.stack
            return OpcodeResult(
                success=True,
                stack=result.stack,
                explanation=f"{result.explanation} ⚠️ {warning}"
            ), warning
        
        # OP_VERIFY on empty or symbolic stack
        if token_upper == "OP_VERIFY":
            if len(self.stack) < 1:
                self.stack.append("TRUE")
                warning = "Symbolic TRUE assumed for OP_VERIFY (empty stack)."
            elif self.stack[-1].startswith("<") or "symbolic" in self.stack[-1].lower():
                # Symbolic value - assume TRUE
                warning = "Symbolic verification assumed to succeed."
            new_stack = self.stack[:-1] if self.stack else []
            self.stack = new_stack
            return OpcodeResult(
                success=True,
                stack=new_stack,
                explanation=f"OP_VERIFY: Verification passed (symbolic). ⚠️ {warning}"
            ), warning
        
        # OP_EQUALVERIFY with symbolic values
        if token_upper == "OP_EQUALVERIFY":
            if len(self.stack) < 2:
                self.stack = ["<symbolic_a>", "<symbolic_b>"] + self.stack
                warning = "Symbolic values assumed for OP_EQUALVERIFY."
            new_stack = self.stack[:-2] if len(self.stack) >= 2 else []
            warning = warning or "Symbolic verification assumed to succeed."
            self.stack = new_stack
            return OpcodeResult(
                success=True,
                stack=new_stack,
                explanation=f"OP_EQUALVERIFY: Symbolic equality verified. ⚠️ {warning}"
            ), warning
        
        # OP_CHECKSIG with missing items
        if token_upper == "OP_CHECKSIG":
            if len(self.stack) < 2:
                missing = 2 - len(self.stack)
                for _ in range(missing):
                    self.stack.insert(0, "<assumed_signature>" if len(self.stack) == 0 else "<assumed_public_key>")
                if missing == 2:
                    self.stack = ["<assumed_signature>", "<assumed_public_key>"]
                warning = "Symbolic signature and public key assumed for educational execution."
            new_stack = self.stack[:-2] + ["TRUE"]
            self.stack = new_stack
            return OpcodeResult(
                success=True,
                stack=new_stack,
                explanation=f"OP_CHECKSIG: Signature verified (symbolic). ⚠️ {warning}"
            ), warning
        
        # OP_HASH160 on empty stack
        if token_upper == "OP_HASH160" and len(self.stack) < 1:
            self.stack.append("<symbolic_input>")
            warning = "Symbolic input injected for OP_HASH160."
            result = OPCODE_HANDLERS[token_upper](self.stack)
            self.stack = result.stack
            return OpcodeResult(
                success=True,
                stack=result.stack,
                explanation=f"{result.explanation} ⚠️ {warning}"
            ), warning
        
        # OP_EQUAL on insufficient stack
        if token_upper == "OP_EQUAL" and len(self.stack) < 2:
            while len(self.stack) < 2:
                self.stack.insert(0, "<symbolic_value>")
            warning = "Symbolic values assumed for OP_EQUAL."
            result = OPCODE_HANDLERS[token_upper](self.stack)
            self.stack = result.stack
            return OpcodeResult(
                success=True,
                stack=result.stack,
                explanation=f"{result.explanation} ⚠️ {warning}"
            ), warning
        
        # Default: return original failed result
        return failed_result, None
    
    def _get_symbolic_initial_stack(self, script_type: str, tokens: List[str]) -> List[str]:
        """
        Get the symbolic initial stack based on STRUCTURAL pattern detection.
        
        In real Bitcoin execution, the unlocking script (scriptSig) runs first
        and pushes data onto the stack. This simulates that preloaded state.
        
        IMPORTANT: Uses structural detection, not just type labels.
        """
        from .detector import P2PKH, P2SH, P2PK, MULTISIG, NULL_DATA, P2WPKH, P2WSH, P2TR
        
        # First check by type label
        if script_type == P2PKH:
            return ["<signature>", "<public_key>"]
        
        elif script_type == P2SH:
            return ["<signature>", "<redeem_script>"]
        
        elif script_type == P2PK:
            return ["<signature>"]
        
        elif script_type == MULTISIG:
            from .detector import parse_small_num
            if tokens and len(tokens) >= 1:
                m = parse_small_num(tokens[0])
                if m > 0:
                    return ["<dummy>"] + [f"<sig{i+1}>" for i in range(m)]
            return ["<dummy>", "<sig1>", "<sig2>"]
        
        elif script_type in [P2WPKH, P2WSH]:
            return []
        
        elif script_type == P2TR:
            return []
        
        elif script_type == NULL_DATA:
            return []
        
        # STRUCTURAL PATTERN DETECTION for Unknown scripts
        # Check if script STRUCTURALLY matches known patterns
        return self._detect_structural_stack(tokens)
    
    def _detect_structural_stack(self, tokens: List[str]) -> List[str]:
        """
        Detect required symbolic stack based on STRUCTURAL patterns in the script.
        
        This handles scripts labeled as "Unknown" that still structurally
        require unlocking data.
        """
        if not tokens:
            return []
        
        normalized = [t.upper() if t.upper().startswith("OP_") else t for t in tokens]
        
        # STRUCTURAL CHECK: P2PKH-like pattern
        # Starts with OP_DUP OP_HASH160, ends with OP_EQUALVERIFY OP_CHECKSIG
        if len(normalized) >= 5:
            if (normalized[0] == "OP_DUP" and 
                normalized[1] == "OP_HASH160" and
                normalized[-2] == "OP_EQUALVERIFY" and
                normalized[-1] == "OP_CHECKSIG"):
                return ["<signature>", "<public_key>"]
        
        # STRUCTURAL CHECK: P2SH-like pattern
        # Starts with OP_HASH160, ends with OP_EQUAL
        if len(normalized) >= 3:
            if (normalized[0] == "OP_HASH160" and 
                normalized[-1] == "OP_EQUAL"):
                return ["<signature>", "<redeem_script>"]
        
        # STRUCTURAL CHECK: Multisig-like pattern
        # Ends with OP_CHECKMULTISIG
        if "OP_CHECKMULTISIG" in normalized:
            from .detector import parse_small_num, is_small_num
            if len(normalized) >= 4 and is_small_num(normalized[0]):
                m = parse_small_num(normalized[0])
                if m > 0:
                    return ["<dummy>"] + [f"<sig{i+1}>" for i in range(m)]
            return ["<dummy>", "<sig1>", "<sig2>"]
        
        # STRUCTURAL CHECK: P2PK-like pattern
        # Ends with OP_CHECKSIG (but not P2PKH structure)
        if normalized[-1] == "OP_CHECKSIG" and "OP_DUP" not in normalized:
            return ["<signature>"]
        
        # STRUCTURAL CHECK: Uses opcodes that typically consume stack items
        # Provide generic symbolic input
        stack_consuming_ops = ["OP_DUP", "OP_HASH160", "OP_HASH256", "OP_SHA256", 
                               "OP_CHECKSIG", "OP_CHECKMULTISIG", "OP_EQUALVERIFY", "OP_EQUAL"]
        
        if any(op in normalized for op in stack_consuming_ops):
            # Script uses stack-consuming opcodes but doesn't match templates
            return ["<symbolic_input>"]
        
        # No stack preloading needed (e.g., pure data scripts, OP_RETURN handled above)
        return []
    
    def _get_initial_stack_message(self, script_type: str, initial_stack: List[str]) -> str:
        """Generate educational message about the initial stack."""
        from .detector import NULL_DATA, P2WPKH, P2WSH, P2TR, UNKNOWN
        
        if script_type == NULL_DATA:
            return "OP_RETURN scripts are provably unspendable - no unlocking script required."
        
        if script_type in [P2WPKH, P2WSH, P2TR]:
            return "SegWit/Taproot witness data is provided separately from the scriptPubKey."
        
        if not initial_stack:
            return "Initial stack is empty. This script may be custom or may require specific unlock conditions."
        
        stack_display = ", ".join(initial_stack)
        
        # Check if this was a symbolic input assumption
        if "<symbolic_input>" in initial_stack:
            return (
                f"Initial Symbolic Stack: [{stack_display}]\n"
                f"⚠️ Symbolic input assumed for educational execution. "
                f"This script uses stack operations but doesn't match standard templates."
            )
        
        return (
            f"Initial Symbolic Stack (represents scriptSig execution): [{stack_display}]\n"
            f"This stack is preloaded to represent data pushed by the unlocking script "
            f"(scriptSig) in real Bitcoin execution."
        )
    
    def _execute_token(self, token: str) -> OpcodeResult:
        """
        Execute a single token (opcode or data push).
        
        Args:
            token: The token to execute
            
        Returns:
            OpcodeResult with execution details
        """
        token_upper = token.upper()
        
        # Check if it's a known opcode
        if token_upper in OPCODE_HANDLERS:
            result = OPCODE_HANDLERS[token_upper](self.stack)
            self.stack = result.stack
            return result
        
        # Check if it's an unknown opcode
        if is_opcode(token):
            # Unknown opcode - treat as no-op for educational purposes
            return OpcodeResult(
                success=True,
                stack=self.stack,
                explanation=f"{token}: Unknown opcode (treated as no-op for demonstration)"
            )
        
        # It's a data push
        result = execute_data_push(token, self.stack)
        self.stack = result.stack
        return result
    
    def _generate_summary(
        self,
        script: str,
        script_type: str,
        type_description: str,
        success: bool,
        parse_warning: str,
        initial_stack_message: str = "",
        warnings: list = None
    ) -> str:
        """
        Generate a plain English summary of the script.
        
        Args:
            script: Original script
            script_type: Detected script type
            type_description: Description of the script type
            success: Whether execution was successful
            parse_warning: Any warnings from parsing
            initial_stack_message: Educational message about initial stack
            warnings: List of forgiving execution warnings
            
        Returns:
            Human-readable summary
        """
        parts = []
        
        # Script type info
        parts.append(f"Script Type: {script_type}")
        parts.append(f"\n{type_description}")
        
        # Initial stack message (educational)
        if initial_stack_message:
            parts.append(f"\n\n{initial_stack_message}")
        
        # Execution summary
        if success:
            parts.append(f"\nExecution: Completed successfully with {len(self.steps)} steps.")
            
            if self.stack:
                parts.append(f"Final stack contains {len(self.stack)} item(s): {', '.join(self.stack)}")
            else:
                parts.append("Final stack is empty.")
        else:
            parts.append(f"\nExecution: Failed during step {len(self.steps)}.")
        
        # Forgiving execution warnings
        if warnings:
            parts.append("\n\n⚠️ FORGIVING EXECUTION WARNINGS:")
            for w in warnings:
                parts.append(f"  • {w}")
        
        # Parse warnings
        if parse_warning:
            parts.append(f"\nWarning: {parse_warning}")
        
        # Educational note
        parts.append("\n\n⚠️ DISCLAIMER: This is a symbolic simulation for educational purposes. "
                    "It does not perform real cryptographic operations and should not be used "
                    "for validating actual Bitcoin transactions.")
        
        return "\n".join(parts)


def explain_script(script: str) -> ScriptExplanation:
    """
    Convenience function to explain a Bitcoin Script.
    
    Args:
        script: Bitcoin Script in ASM format
        
    Returns:
        ScriptExplanation with complete breakdown
    """
    explainer = Explainer()
    return explainer.explain(script)


def get_opcode_info(opcode: str) -> dict:
    """
    Get information about a specific opcode.
    
    Args:
        opcode: Opcode name (e.g., "OP_DUP")
        
    Returns:
        Dictionary with opcode information
    """
    opcode_upper = opcode.upper()
    
    is_known = opcode_upper in OPCODE_HANDLERS
    
    return {
        "opcode": opcode_upper,
        "known": is_known,
        "description": get_opcode_description(opcode_upper) if is_known else "Unknown opcode"
    }
