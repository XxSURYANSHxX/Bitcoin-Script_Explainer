# Bitcoin Script Explainer

An educational tool for understanding Bitcoin Script, the stack-based programming language used in Bitcoin transactions.

![Bitcoin Script Explainer](https://img.shields.io/badge/Bitcoin-Script%20Explainer-orange?style=for-the-badge&logo=bitcoin)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green?style=flat-square)

---

## 📖 What is Bitcoin Script?

Bitcoin Script is a simple, stack-based programming language used to define spending conditions for Bitcoin transactions. Every Bitcoin transaction contains scripts that specify:

- **ScriptPubKey (Locking Script)**: Conditions that must be met to spend the output
- **ScriptSig (Unlocking Script)**: Data that satisfies those conditions

Script is intentionally not Turing-complete — it lacks loops and complex control flow — to prevent denial-of-service attacks on the Bitcoin network.

### How Script Works

Bitcoin Script uses a **stack-based execution model**:

1. Data is pushed onto a stack
2. Opcodes pop data, perform operations, and push results
3. A transaction is valid if the stack ends with a truthy value (non-zero)

Example: **P2PKH (Pay-to-Public-Key-Hash)**
```
ScriptPubKey: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
ScriptSig:    <signature> <publicKey>
```

---

## 🎯 Why This Tool?

Learning Bitcoin Script can be challenging because:

- Stack operations are hard to visualize
- Real execution requires cryptographic operations
- Mistakes can lead to lost funds

**This tool provides**:

✅ Step-by-step execution visualization  
✅ Stack state at each operation  
✅ Human-readable explanations  
✅ Script type detection  
✅ Safe, symbolic execution (no real crypto)  

---

## 🚀 Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Setup

1. **Clone or download the project**
   ```bash
   cd btc-script-explainer
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Usage

### Command Line Interface (CLI)

Explain a script directly:

```bash
python cli.py "OP_DUP OP_HASH160 ab6807 OP_EQUALVERIFY OP_CHECKSIG"
```

Interactive mode:

```bash
python cli.py --interactive
```

Read from a file:

```bash
python cli.py --file myscript.txt
```

JSON output:

```bash
python cli.py "OP_DUP OP_HASH160 ab6807 OP_EQUALVERIFY OP_CHECKSIG" --json
```

### Web Interface

Start the server:

```bash
uvicorn backend.main:app --reload
```

Then open your browser to: **http://127.0.0.1:8000**

### API Endpoints

- `POST /explain` - Explain a Bitcoin Script
- `GET /opcodes` - List supported opcodes
- `GET /opcode/{name}` - Get info about a specific opcode
- `GET /docs` - Interactive API documentation

#### Example API Request

```bash
curl -X POST http://127.0.0.1:8000/explain \
  -H "Content-Type: application/json" \
  -d '{"script": "OP_DUP OP_HASH160 ab6807 OP_EQUALVERIFY OP_CHECKSIG"}'
```

---

## 📋 Example Input/Output

### Input
```
OP_DUP OP_HASH160 ab68025513c3dbd2f7b92a94e0581f5d50f654e7 OP_EQUALVERIFY OP_CHECKSIG
```

### Output

```
Script Type: P2PKH (Pay-to-Public-Key-Hash)

[Step 1] OP_DUP
  Explanation: OP_DUP: Duplicated 'ab68025513c3dbd2f7b92a94e0581f5d50f654e7' on top of the stack
  Stack Before: (empty)
  Stack After: ab68025513c3dbd2f7b92a94e0581f5d50f654e7

[Step 2] OP_HASH160
  Explanation: OP_HASH160: Replaced 'ab68025513c3dbd2f7b92a94e0581f5d50f654e7' with its HASH160 (symbolic)
  Stack Before: ab68025513c3dbd2f7b92a94e0581f5d50f654e7
  Stack After: HASH160(ab68025513c3dbd2f7b92a94e0581f5d50f654e7)

... (continues for each step)

Summary:
This is a Pay-to-Public-Key-Hash script. It requires a signature and 
public key that hashes to the embedded hash.
```

---

## ⚙️ Supported Opcodes

| Opcode | Description |
|--------|-------------|
| `OP_DUP` | Duplicates the top stack item |
| `OP_HASH160` | Performs RIPEMD160(SHA256(x)) on top item |
| `OP_EQUAL` | Compares top two items, pushes TRUE/FALSE |
| `OP_EQUALVERIFY` | Same as OP_EQUAL but fails if FALSE |
| `OP_CHECKSIG` | Verifies signature against public key |
| `OP_CHECKMULTISIG` | Verifies M-of-N multisig |
| `OP_VERIFY` | Fails if top item is FALSE |
| `OP_RETURN` | Marks output as unspendable (data embedding) |
| Data pushes | Hex literals pushed to stack |

---

## 🔍 Script Type Detection

The tool automatically detects common script patterns:

| Type | Pattern | Description |
|------|---------|-------------|
| **P2PKH** | `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG` | Standard Bitcoin address |
| **P2SH** | `OP_HASH160 <hash> OP_EQUAL` | Script hash (multisig, SegWit) |
| **P2PK** | `<pubkey> OP_CHECKSIG` | Legacy pay-to-public-key |
| **Multisig** | `M <keys...> N OP_CHECKMULTISIG` | Multi-signature |
| **Null Data** | `OP_RETURN <data>` | Data embedding (unspendable) |

---

## ⚠️ Limitations

This tool is **educational only** and has important limitations:

1. **No Real Cryptography**: Signature verification and hashing are symbolic. The tool does not perform actual cryptographic operations.

2. **Not a Consensus Validator**: This tool does NOT validate scripts according to Bitcoin consensus rules. It cannot be used to verify real transactions.

3. **Simplified Execution**: Some edge cases and complex opcodes are not fully implemented.

4. **ScriptSig Not Concatenated**: In real Bitcoin, ScriptSig and ScriptPubKey are concatenated. This tool analyzes them separately.

5. **Limited Opcode Support**: Only a subset of Bitcoin Script opcodes is implemented.

**DO NOT USE THIS TOOL TO:**
- Validate real Bitcoin transactions
- Make decisions about sending or receiving Bitcoin
- Audit smart contracts or complex scripts

---

## 📁 Project Structure

```
btc-script-explainer/
├── backend/
│   ├── __init__.py      # Package exports
│   ├── main.py          # FastAPI application
│   ├── explainer.py     # Core explanation logic
│   ├── parser.py        # Script tokenizer
│   ├── opcodes.py       # Opcode implementations
│   ├── detector.py      # Script type detection
│   └── models.py        # Pydantic models
├── frontend/
│   ├── index.html       # Web UI
│   ├── style.css        # Styling
│   └── app.js           # JavaScript logic
├── cli.py               # Command line interface
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

---

## 🔮 Future Improvements

Potential enhancements for future versions:

- [ ] More opcodes (OP_IF, OP_ELSE, OP_ENDIF, etc.)
- [ ] SegWit script support (P2WPKH, P2WSH)
- [ ] Taproot/Tapscript support
- [ ] Combined ScriptSig + ScriptPubKey execution
- [ ] Transaction hex parsing
- [ ] Visual stack animation
- [ ] Export to different formats
- [ ] Unit test suite

---

## 📚 Resources

Learn more about Bitcoin Script:

- [Bitcoin Wiki - Script](https://en.bitcoin.it/wiki/Script)
- [Learn Me a Bitcoin - Script](https://learnmeabitcoin.com/technical/script)
- [Bitcoin Developer Guide](https://developer.bitcoin.org/devguide/transactions.html)
- [BIP-16 (P2SH)](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)

---

## 📄 License

This project is open source and available for educational use.

---

**Made for Bitcoin developers and learners** 🧡
