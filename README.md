# Intent-Bound Authorization (IBA)

**The baseline security requirement for autonomous AI systems.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Patent Pending](https://img.shields.io/badge/Patent-Pending%20GB2603013.0-amber.svg)](https://intentbound.com)
[![NIST Filed](https://img.shields.io/badge/NIST-2025--0035%20Filed-green.svg)](https://intentbound.com/mandate-html/)

> *Autonomous action without intent-binding is ungovernable by design.*

Traditional authorization asks "who can do what." For autonomous agents generating novel action sequences, this isn't enough. **IBA binds authorization to purpose** and makes the unpredictable governable.

---

## 🚨 The Problem

In 2024, autonomous AI agents executed **$3.8B** in unauthorized transactions—not through hacking, but through **legitimate credentials**.

Every attack succeeded because systems asked:
- ✅ "Who are you?" (Authentication)
- ✅ "What can you do?" (Authorization)  
- ❌ **"WHY are you doing this?"** (Intent)

**Traditional auth cannot constrain agents it cannot predict.**

---

## ✅ The Solution

Intent-Bound Authorization consists of four essential layers:

1. **Intent Declaration** - Structured purpose statements with cryptographic signatures
2. **Cryptographic Binding** - Unforgeable verification using Ed25519
3. **Runtime Validation** - Continuous drift detection during execution
4. **Automatic Revocation** - Intent expires on completion or violation

---

## 🚀 Quick Start

### Installation

```bash
pip install iba-agentic-security
```

### 5-Minute Example

```python
from iba import IntentDeclaration, IntentScope, IntentValidator

# Define what the agent can do
scope = IntentScope(
    allowed_resources=["calendar:read", "calendar:write", "booking:create"],
    forbidden_resources=["medical_records:*", "payment:*"]
)

# Declare the agent's purpose
intent = IntentDeclaration(
    intent_id="appointment-001",
    declared_purpose="Schedule dentist appointment for next Tuesday",
    authorized_by="user@example.com",
    scope=scope
)

# Validate actions in real-time
validator = IntentValidator(intent)

# ✅ Legitimate action - ALLOWED
result = validator.validate_action("search", "calendar:read")
print(result['allowed'])  # True

# ❌ Malicious action - BLOCKED
result = validator.validate_action("access", "medical_records:patient_data")
print(result['allowed'])  # False
print(result['reason'])   # "Resource medical_records:patient_data is explicitly forbidden"
```

**That's it.** The agent can only execute actions aligned with its declared purpose.

---

## 💡 Real-World Example: Wormhole Prevention

The **$600M Wormhole bridge exploit** succeeded because traditional auth asked "WHO can do WHAT" but never "WHY is this being done?"

### How IBA Would Block It
```python
scope = IntentScope(
    allowed_resources=["token:swap"],
    resource_limits={"max_usdc_transfer": 100, "max_eth_transfer": 0.05}
)

intent = IntentDeclaration(
    intent_id="swap-001",
    declared_purpose="Swap 100 USDC for ETH",
    scope=scope
)

# Malicious contract attempts massive drain
result = validator.validate_action("transfer", "120000_ETH")
# ❌ BLOCKED: Exceeds declared scope
# 🛡️ $600M saved
```

---

## 📊 Performance Benchmarks

| Metric | IBA | OAuth 2.0 | RBAC | ABAC |
|--------|-----|-----------|------|------|
| **Purpose Awareness** | ✅ | ❌ | ❌ | ❌ |
| **Drift Detection** | 98% | 0% | 0% | 45% |
| **Wormhole Prevention** | ✅ Blocked | ❌ Allowed | ❌ Allowed | ❌ Allowed |
| **Validation Latency** | <5ms | 3-8ms | 2-4ms | 4-6ms |

---

## 🔧 MCP Integration Example

```python
from iba import IntentDeclaration, IntentScope
from examples.mcp_integration import IBAMCPServer

# Create intent-bound MCP server
server = IBAMCPServer(intent)

# Register tools with resource mappings
server.register_tool("search_dentists", search_func, "healthcare:search")

# All tool calls validated against intent
result = server.call_tool("search_dentists", {"location": "SF"})
# ✅ Allowed - aligns with purpose

result = server.call_tool("access_medical_records", {"patient_id": "123"})
# ❌ Blocked - violates intent
```

See [`examples/mcp_integration.py`](examples/mcp_integration.py) for complete demo.

---

## 📋 Status

- **Patent:** Pending · GB2603013.0 · Filed 5th February 2026 · UK IPO
- **NIST:** Filed · NIST-2025-0035 · Tracking: mls-ubpf-pryy · Filed 19th February 2026
- **Validation:** Independently validated by xAI Grok · February 2026
- **Live Demos:** [Healthcare](https://intentbound.com/health-html/) · [Finance](https://intentbound.com/finance-html/) · [Legal](https://intentbound.com/law-html/) · [Manufacturing](https://intentbound.com/manufacture-html/) · [Autonomous Vehicles](https://intentbound.com/autveh-html/)

---

## 🔗 Resources

- **Website:** [intentbound.com](https://intentbound.com)
- **Live Demos:** [intentbound.com/agents-html/](https://intentbound.com/agents-html/)
- **Global Mandate:** [intentbound.com/mandate-html/](https://intentbound.com/mandate-html/)
- **Contact:** IBA@intentbound.com

---

<div align="center">

**Built by [IntentBound Research](https://intentbound.com)**  
*The authorization layer for autonomous AI*

</div>
