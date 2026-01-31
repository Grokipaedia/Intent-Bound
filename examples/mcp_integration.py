"""
IBA + Anthropic MCP Integration Example

This example shows how to integrate Intent-Bound Authorization with
Anthropic's Model Context Protocol (MCP) to create purpose-aware AI agents.

The integration provides:
1. Intent validation before tool execution
2. Automatic drift detection
3. Comprehensive audit logging
4. Real-time violation blocking

Author: Grokipaedia Research
License: MIT
"""

import sys
sys.path.insert(0, '..')

from iba import (
    IntentDeclaration,
    IntentScope,
    IntentValidator,
    IntentViolationError
)
from typing import Any, Dict, Optional
from datetime import datetime
import json


class IBAMCPServer:
    """
    An MCP Server with Intent-Bound Authorization.
    
    This wraps the standard MCP Server to add intent validation
    before every tool call.
    """
    
    def __init__(self, intent: IntentDeclaration, verbose: bool = True):
        """
        Initialize IBA-enabled MCP server.
        
        Args:
            intent: The IntentDeclaration defining what this agent can do
            verbose: Whether to print validation results
        """
        self.intent = intent
        self.validator = IntentValidator(intent)
        self.verbose = verbose
        self.tools: Dict[str, Any] = {}
        
        if verbose:
            print(f"🔐 IBA MCP Server initialized")
            print(f"📋 Purpose: {intent.declared_purpose}")
            print(f"👤 Authorized by: {intent.authorized_by}")
            print(f"⏰ Valid until: {intent.expiration.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print()
    
    def register_tool(self, name: str, func: Any, resource: str):
        """
        Register a tool with its associated resource.
        
        Args:
            name: Tool name
            func: Tool function
            resource: Resource identifier (e.g., "calendar:write")
        """
        self.tools[name] = {
            'function': func,
            'resource': resource
        }
        if self.verbose:
            print(f"🔧 Registered tool: {name} → {resource}")
    
    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call a tool with intent validation.
        
        This is the core integration point. Every tool call goes through
        intent validation before execution.
        """
        if name not in self.tools:
            return {
                'success': False,
                'error': f"Unknown tool: {name}"
            }
        
        tool = self.tools[name]
        resource = tool['resource']
        
        # PRE-EXECUTION GATE: Validate against intent
        validation_result = self.validator.validate_action(name, resource)
        
        if not validation_result['allowed']:
            # Intent violation detected - block execution
            if self.verbose:
                print(f"\n❌ BLOCKED: {name}")
                print(f"   Resource: {resource}")
                print(f"   Reason: {validation_result['reason']}")
                print()
            
            # Check for drift
            drift = self.validator.detect_drift()
            if drift['drift_detected']:
                if self.verbose:
                    print(f"⚠️  DRIFT DETECTED: {drift['reason']}")
                    print(f"   Intent may be compromised")
                    print()
            
            return {
                'success': False,
                'error': validation_result['reason'],
                'intent_violation': True,
                'drift_detected': drift['drift_detected']
            }
        
        # Validation passed - execute tool
        if self.verbose:
            print(f"✅ ALLOWED: {name}")
            print(f"   Resource: {resource}")
            print(f"   Purpose alignment: Verified")
            print()
        
        try:
            result = tool['function'](**arguments)
            
            # POST-EXECUTION: Log success
            return {
                'success': True,
                'result': result,
                'validated_by_iba': True
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_audit_log(self) -> list:
        """Get the complete audit log of all actions."""
        return self.validator.get_action_log()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about agent behavior."""
        return self.validator.get_statistics()


# ============================================================================
# EXAMPLE: Healthcare Appointment Scheduler
# ============================================================================

def search_dentists(location: str) -> list:
    """Simulated dentist search."""
    return [
        {"name": "Dr. Smith", "address": "123 Main St", "rating": 4.8},
        {"name": "Dr. Johnson", "address": "456 Oak Ave", "rating": 4.9}
    ]


def read_calendar(date_range: str) -> list:
    """Simulated calendar read."""
    return [
        {"date": "2026-02-05", "time": "14:00", "available": True},
        {"date": "2026-02-06", "time": "10:00", "available": True}
    ]


def create_appointment(dentist: str, date: str, time: str) -> dict:
    """Simulated appointment creation."""
    return {
        "appointment_id": "apt-001",
        "dentist": dentist,
        "date": date,
        "time": time,
        "confirmed": True
    }


def access_medical_records(patient_id: str) -> dict:
    """Simulated medical records access - should be BLOCKED."""
    return {"patient_id": patient_id, "records": "SENSITIVE DATA"}


def modify_insurance(patient_id: str, plan: str) -> dict:
    """Simulated insurance modification - should be BLOCKED."""
    return {"patient_id": patient_id, "plan": plan}


def demo_healthcare_agent():
    """
    Demonstrate IBA preventing unauthorized healthcare data access.
    
    This example shows the dentist appointment scenario from the
    architecture documentation.
    """
    print("=" * 70)
    print("DEMO: Healthcare Appointment Scheduler with IBA")
    print("=" * 70)
    print()
    
    # Define intent scope
    scope = IntentScope(
        allowed_resources=[
            "calendar:read",
            "calendar:write",
            "healthcare:search",
            "booking:create"
        ],
        forbidden_resources=[
            "medical_records:*",
            "insurance:*",
            "payment:modify"
        ],
        resource_limits={
            "max_api_calls": 50
        }
    )
    
    # Create intent declaration
    intent = IntentDeclaration(
        intent_id="healthcare-001",
        declared_purpose="Schedule dentist appointment for next Tuesday",
        authorized_by="user@example.com",
        scope=scope
    )
    
    # Create IBA-enabled MCP server
    server = IBAMCPServer(intent, verbose=True)
    
    # Register tools
    server.register_tool("search_dentists", search_dentists, "healthcare:search")
    server.register_tool("read_calendar", read_calendar, "calendar:read")
    server.register_tool("create_appointment", create_appointment, "booking:create")
    server.register_tool("access_medical_records", access_medical_records, "medical_records:read")
    server.register_tool("modify_insurance", modify_insurance, "insurance:modify")
    
    print("\n" + "─" * 70)
    print("SCENARIO 1: Legitimate Actions (Should Succeed)")
    print("─" * 70 + "\n")
    
    # Legitimate action 1: Search dentists
    result = server.call_tool("search_dentists", {"location": "San Francisco"})
    
    # Legitimate action 2: Read calendar
    result = server.call_tool("read_calendar", {"date_range": "2026-02-01 to 2026-02-07"})
    
    # Legitimate action 3: Create appointment
    result = server.call_tool("create_appointment", {
        "dentist": "Dr. Smith",
        "date": "2026-02-05",
        "time": "14:00"
    })
    
    print("\n" + "─" * 70)
    print("SCENARIO 2: Malicious Actions (Should Be Blocked)")
    print("─" * 70 + "\n")
    
    # Malicious action 1: Try to access medical records
    result = server.call_tool("access_medical_records", {"patient_id": "12345"})
    
    # Malicious action 2: Try to modify insurance
    result = server.call_tool("modify_insurance", {"patient_id": "12345", "plan": "premium"})
    
    # Try again - should trigger drift detection
    result = server.call_tool("access_medical_records", {"patient_id": "67890"})
    result = server.call_tool("modify_insurance", {"patient_id": "67890", "plan": "basic"})
    
    print("\n" + "─" * 70)
    print("STATISTICS & AUDIT")
    print("─" * 70 + "\n")
    
    # Get statistics
    stats = server.get_statistics()
    print("📊 Agent Statistics:")
    print(f"   Total actions: {stats['total_actions']}")
    print(f"   Allowed: {stats['allowed']}")
    print(f"   Blocked: {stats['blocked']}")
    print(f"   Violation rate: {stats['violation_rate']:.1%}")
    print()
    
    # Get audit log
    print("📋 Audit Log:")
    for i, action in enumerate(server.get_audit_log(), 1):
        status = "✅" if action['allowed'] else "❌"
        print(f"   {i}. {status} {action['action']} → {action['resource']}")
        if not action['allowed']:
            print(f"      Reason: {action['reason']}")
    
    print("\n" + "=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print("\nKey Takeaways:")
    print("• Legitimate actions executed successfully")
    print("• Malicious actions blocked before execution")
    print("• Drift detection triggered after repeated violations")
    print("• Complete audit trail maintained")
    print("\nThis is IBA in action. Traditional OAuth would have allowed")
    print("the medical records access (valid credentials, authorized user).")
    print("\nIBA prevented it because it violated the declared purpose.")


if __name__ == "__main__":
    demo_healthcare_agent()
