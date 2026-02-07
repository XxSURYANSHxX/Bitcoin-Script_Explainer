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
        
        # Detect script type
        script_type, type_description = detect_script_type(tokens)
        
        # Execute each token
        success = True
        error_message = None
        
        for i, token in enumerate(tokens):
            stack_before = self.stack.copy()
            
            try:
                result = self._execute_token(token)
                
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
            parse_warning=parse_warning
        )
        
        return ScriptExplanation(
            script=script,
            script_type=script_type,
            steps=self.steps,
            summary=summary,
            success=success,
            error=error_message
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
        parse_warning: str
    ) -> str:
        """
        Generate a plain English summary of the script.
        
        Args:
            script: Original script
            script_type: Detected script type
            type_description: Description of the script type
            success: Whether execution was successful
            parse_warning: Any warnings from parsing
            
        Returns:
            Human-readable summary
        """
        parts = []
        
        # Script type info
        parts.append(f"Script Type: {script_type}")
        parts.append(f"\n{type_description}")
        
        # Execution summary
        if success:
            parts.append(f"\nExecution: Completed successfully with {len(self.steps)} steps.")
            
            if self.stack:
                parts.append(f"Final stack contains {len(self.stack)} item(s): {', '.join(self.stack)}")
            else:
                parts.append("Final stack is empty.")
        else:
            parts.append(f"\nExecution: Failed during step {len(self.steps)}.")
        
        # Warnings
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
