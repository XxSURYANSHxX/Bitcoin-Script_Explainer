"""
Bitcoin Script Explainer Backend Package.

This package provides the core functionality for parsing, explaining,
and simulating Bitcoin Script execution.
"""

from .explainer import explain_script, Explainer
from .parser import parse_script, tokenize_script
from .detector import detect_script_type
from .models import ScriptRequest, ScriptExplanation, StackState

__all__ = [
    "explain_script",
    "Explainer",
    "parse_script",
    "tokenize_script",
    "detect_script_type",
    "ScriptRequest",
    "ScriptExplanation",
    "StackState",
]
