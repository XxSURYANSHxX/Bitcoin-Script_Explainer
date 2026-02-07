"""
FastAPI backend for Bitcoin Script Explainer.

This module provides the REST API endpoints for the Bitcoin Script Explainer tool.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from .models import ScriptRequest, ScriptExplanation, ErrorResponse
from .explainer import explain_script, get_opcode_info
from .parser import ParseError


# Create FastAPI application
app = FastAPI(
    title="Bitcoin Script Explainer",
    description="""
    An educational tool for understanding Bitcoin Script.
    
    This API provides:
    - Step-by-step script explanation
    - Symbolic stack simulation
    - Script type detection
    - Opcode documentation
    
    **Disclaimer**: This is an educational tool and NOT a consensus-level validator.
    It uses symbolic execution and does not perform real cryptographic operations.
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post(
    "/explain",
    response_model=ScriptExplanation,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid script provided"},
        500: {"model": ErrorResponse, "description": "Internal server error"}
    },
    summary="Explain a Bitcoin Script",
    description="Parse and explain a Bitcoin Script in ASM format, showing step-by-step execution."
)
async def explain_bitcoin_script(request: ScriptRequest) -> ScriptExplanation:
    """
    Explain a Bitcoin Script.
    
    Takes a Bitcoin Script in ASM format and returns:
    - Step-by-step execution breakdown
    - Stack state at each step
    - Detected script type
    - Plain English summary
    
    Example input: "OP_DUP OP_HASH160 ab6807 OP_EQUALVERIFY OP_CHECKSIG"
    """
    try:
        result = explain_script(request.script)
        
        # If parsing failed completely, return 400
        if result.script_type == "Error" and not result.success:
            raise HTTPException(
                status_code=400,
                detail=result.error or "Invalid script"
            )
        
        return result
        
    except ParseError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Internal error: {str(e)}"
        )


@app.get(
    "/opcode/{opcode}",
    summary="Get opcode information",
    description="Get information about a specific Bitcoin Script opcode."
)
async def get_opcode(opcode: str) -> dict:
    """
    Get information about a specific opcode.
    
    Returns:
    - opcode: The opcode name
    - known: Whether the opcode is supported
    - description: Human-readable description
    """
    return get_opcode_info(opcode)


@app.get(
    "/opcodes",
    summary="List supported opcodes",
    description="Get a list of all supported opcodes with descriptions."
)
async def list_opcodes() -> dict:
    """
    List all supported opcodes.
    
    Returns a dictionary of opcode names to descriptions.
    """
    from .opcodes import OPCODE_DESCRIPTIONS
    return {
        "supported_opcodes": OPCODE_DESCRIPTIONS,
        "note": "This tool supports a subset of Bitcoin Script opcodes for educational purposes."
    }


@app.get(
    "/health",
    summary="Health check",
    description="Check if the API is running."
)
async def health_check() -> dict:
    """Health check endpoint."""
    return {"status": "healthy", "service": "btc-script-explainer"}


# Serve static frontend files
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")

if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")
    
    @app.get("/", include_in_schema=False)
    async def serve_frontend():
        """Serve the frontend index.html."""
        return FileResponse(os.path.join(frontend_path, "index.html"))
