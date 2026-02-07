#!/usr/bin/env python3
"""
Bitcoin Script Explainer - Command Line Interface

A CLI tool for explaining Bitcoin Script in ASM format.
Provides step-by-step execution breakdown and script type detection.

Usage:
    python cli.py "OP_DUP OP_HASH160 ab6807 OP_EQUALVERIFY OP_CHECKSIG"
    python cli.py --file script.txt
    python cli.py --interactive

DISCLAIMER: This is an educational tool and NOT a consensus-level validator.
"""

import argparse
import sys
from typing import Optional

# Add parent directory to path for imports when running directly
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.explainer import explain_script
from backend.models import ScriptExplanation


# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


def supports_color() -> bool:
    """Check if the terminal supports ANSI colors."""
    # Check for Windows
    if sys.platform == 'win32':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # Enable ANSI escape sequences on Windows 10+
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return os.environ.get('TERM') is not None
    
    # Check for TTY and TERM environment variable
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()


def colorize(text: str, color: str) -> str:
    """Apply color to text if terminal supports it."""
    if supports_color():
        return f"{color}{text}{Colors.ENDC}"
    return text


def print_header():
    """Print the CLI header."""
    header = """
╔══════════════════════════════════════════════════════════════╗
║                  Bitcoin Script Explainer                    ║
║              Educational Tool for Bitcoin Script             ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(colorize(header, Colors.YELLOW))


def print_explanation(result: ScriptExplanation):
    """Print the script explanation in a formatted way."""
    
    # Script Type
    print(colorize("\n━━━ Script Type ━━━", Colors.BOLD))
    print(colorize(result.script_type, Colors.CYAN))
    
    # Execution Status
    if result.success:
        print(colorize("\n✓ Execution completed successfully", Colors.GREEN))
    else:
        print(colorize(f"\n✗ Execution failed: {result.error}", Colors.RED))
    
    # Step-by-step execution
    print(colorize("\n━━━ Step-by-Step Execution ━━━", Colors.BOLD))
    
    for step in result.steps:
        step_num = step.step + 1
        print(colorize(f"\n[Step {step_num}]", Colors.YELLOW), end=" ")
        print(colorize(step.opcode, Colors.CYAN + Colors.BOLD))
        
        print(colorize("  Explanation: ", Colors.DIM), end="")
        print(step.explanation)
        
        # Stack before
        stack_before = " | ".join(step.stack_before) if step.stack_before else "(empty)"
        print(colorize("  Stack Before: ", Colors.DIM), end="")
        print(colorize(stack_before, Colors.BLUE))
        
        # Stack after
        stack_after = " | ".join(step.stack_after) if step.stack_after else "(empty)"
        print(colorize("  Stack After:  ", Colors.DIM), end="")
        print(colorize(stack_after, Colors.GREEN))
    
    # Summary
    print(colorize("\n━━━ Summary ━━━", Colors.BOLD))
    print(result.summary)
    
    print()  # Final newline


def run_interactive():
    """Run the CLI in interactive mode."""
    print_header()
    print("Interactive mode. Type 'quit' or 'exit' to stop.\n")
    
    while True:
        try:
            script = input(colorize("Enter script> ", Colors.CYAN))
            
            if script.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break
            
            if not script.strip():
                print("Please enter a script or 'quit' to exit.")
                continue
            
            result = explain_script(script)
            print_explanation(result)
            
        except KeyboardInterrupt:
            print("\nInterrupted. Goodbye!")
            break
        except EOFError:
            print("\nGoodbye!")
            break


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Bitcoin Script Explainer - An educational tool for understanding Bitcoin Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py "OP_DUP OP_HASH160 ab6807 OP_EQUALVERIFY OP_CHECKSIG"
  python cli.py --file myscript.txt
  python cli.py --interactive

Supported opcodes:
  OP_DUP, OP_HASH160, OP_EQUAL, OP_EQUALVERIFY, OP_CHECKSIG,
  OP_CHECKMULTISIG, OP_VERIFY, OP_RETURN

DISCLAIMER: This is an educational tool for learning purposes only.
It uses symbolic execution and does NOT perform real cryptographic operations.
        """
    )
    
    parser.add_argument(
        'script',
        nargs='?',
        help='Bitcoin Script in ASM format to explain'
    )
    
    parser.add_argument(
        '-f', '--file',
        type=str,
        help='Read script from a file'
    )
    
    parser.add_argument(
        '-i', '--interactive',
        action='store_true',
        help='Run in interactive mode'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Minimal output (no header, less formatting)'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output result as JSON'
    )
    
    args = parser.parse_args()
    
    # Interactive mode
    if args.interactive:
        run_interactive()
        return
    
    # Get script from file or command line
    script: Optional[str] = None
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                script = f.read().strip()
        except FileNotFoundError:
            print(colorize(f"Error: File not found: {args.file}", Colors.RED), file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(colorize(f"Error reading file: {e}", Colors.RED), file=sys.stderr)
            sys.exit(1)
    elif args.script:
        script = args.script
    else:
        # No script provided, show help
        parser.print_help()
        sys.exit(0)
    
    # Explain the script
    result = explain_script(script)
    
    # Output as JSON
    if args.json:
        import json
        print(json.dumps(result.model_dump(), indent=2))
        return
    
    # Normal output
    if not args.quiet:
        print_header()
    
    print_explanation(result)
    
    # Exit with error code if script execution failed
    if not result.success:
        sys.exit(1)


if __name__ == '__main__':
    main()
