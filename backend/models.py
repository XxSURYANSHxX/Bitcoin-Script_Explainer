"""
Pydantic models for Bitcoin Script Explainer API.
"""

from pydantic import BaseModel, Field
from typing import List, Optional


class ScriptRequest(BaseModel):
    """Request model for script explanation."""
    script: str = Field(
        ...,
        description="Bitcoin Script in ASM format",
        min_length=1,
        examples=["OP_DUP OP_HASH160 ab6807 OP_EQUALVERIFY OP_CHECKSIG"]
    )


class StackState(BaseModel):
    """Represents the stack state at a given step."""
    step: int = Field(..., description="Step number (0-indexed)")
    opcode: str = Field(..., description="The opcode or data being processed")
    stack_before: List[str] = Field(..., description="Stack contents before execution")
    stack_after: List[str] = Field(..., description="Stack contents after execution")
    explanation: str = Field(..., description="Human-readable explanation of the operation")


class ScriptExplanation(BaseModel):
    """Complete explanation of a Bitcoin Script."""
    script: str = Field(..., description="Original input script")
    script_type: str = Field(..., description="Detected script type (P2PKH, P2SH, etc.)")
    steps: List[StackState] = Field(..., description="Step-by-step execution details")
    summary: str = Field(..., description="Plain English summary of the script")
    success: bool = Field(..., description="Whether the script executed without errors")
    error: Optional[str] = Field(None, description="Error message if execution failed")


class ErrorResponse(BaseModel):
    """Error response model."""
    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Additional error details")
