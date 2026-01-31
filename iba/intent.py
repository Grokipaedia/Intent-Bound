"""
Intent-Bound Authorization (IBA) - Core Intent Module

This module provides the fundamental Intent Declaration system that enables
purpose-aware authorization for autonomous AI agents.

Author: Grokipaedia Research
License: MIT
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import hashlib


@dataclass
class IntentScope:
    """Defines what resources an agent can and cannot access."""
    
    allowed_resources: List[str] = field(default_factory=list)
    forbidden_resources: List[str] = field(default_factory=list)
    resource_limits: Dict[str, int] = field(default_factory=dict)
    
    def is_allowed(self, resource: str) -> bool:
        """Check if a resource is explicitly allowed."""
        # Check forbidden first (deny takes precedence)
        for forbidden in self.forbidden_resources:
            if forbidden.endswith('*'):
                # Wildcard match
                prefix = forbidden[:-1]
                if resource.startswith(prefix):
                    return False
            elif resource == forbidden:
                return False
        
        # Check allowed
        for allowed in self.allowed_resources:
            if allowed.endswith('*'):
                # Wildcard match
                prefix = allowed[:-1]
                if resource.startswith(prefix):
                    return True
            elif resource == allowed:
                return True
        
        return False
    
    def is_forbidden(self, resource: str) -> bool:
        """Check if a resource is explicitly forbidden."""
        for forbidden in self.forbidden_resources:
            if forbidden.endswith('*'):
                prefix = forbidden[:-1]
                if resource.startswith(prefix):
                    return True
            elif resource == forbidden:
                return True
        return False


@dataclass
class IntentDeclaration:
    """
    A structured, machine-readable declaration of what an agent intends to do.
    
    This is the core primitive of Intent-Bound Authorization. Every autonomous
    action must be bound to a declared intent.
    """
    
    intent_id: str
    declared_purpose: str
    authorized_by: str
    scope: IntentScope
    timestamp: Optional[datetime] = None
    expiration: Optional[datetime] = None
    success_criteria: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Set defaults for timestamp and expiration if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.expiration is None:
            # Default: 1 hour expiration
            self.expiration = self.timestamp + timedelta(hours=1)
    
    def is_expired(self) -> bool:
        """Check if this intent has expired."""
        return datetime.utcnow() > self.expiration
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "intent_id": self.intent_id,
            "declared_purpose": self.declared_purpose,
            "authorized_by": self.authorized_by,
            "timestamp": self.timestamp.isoformat(),
            "expiration": self.expiration.isoformat(),
            "scope": {
                "allowed_resources": self.scope.allowed_resources,
                "forbidden_resources": self.scope.forbidden_resources,
                "resource_limits": self.scope.resource_limits
            },
            "success_criteria": self.success_criteria,
            "metadata": self.metadata
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)
    
    def get_deterministic_hash(self) -> str:
        """
        Generate a deterministic hash of this intent.
        
        This hash is used for cryptographic binding. The same intent
        will always produce the same hash, enabling verification.
        """
        # Use sorted JSON to ensure deterministic output
        json_str = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IntentDeclaration':
        """Create an IntentDeclaration from a dictionary."""
        scope_data = data.get('scope', {})
        scope = IntentScope(
            allowed_resources=scope_data.get('allowed_resources', []),
            forbidden_resources=scope_data.get('forbidden_resources', []),
            resource_limits=scope_data.get('resource_limits', {})
        )
        
        timestamp = None
        if 'timestamp' in data:
            timestamp = datetime.fromisoformat(data['timestamp'])
        
        expiration = None
        if 'expiration' in data:
            expiration = datetime.fromisoformat(data['expiration'])
        
        return cls(
            intent_id=data['intent_id'],
            declared_purpose=data['declared_purpose'],
            authorized_by=data['authorized_by'],
            scope=scope,
            timestamp=timestamp,
            expiration=expiration,
            success_criteria=data.get('success_criteria', {}),
            metadata=data.get('metadata', {})
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'IntentDeclaration':
        """Create an IntentDeclaration from a JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)


class IntentValidator:
    """
    Validates whether actions align with declared intent.
    
    This is the runtime enforcement layer that prevents drift and
    unauthorized actions.
    """
    
    def __init__(self, intent: IntentDeclaration):
        self.intent = intent
        self.action_log: List[Dict[str, Any]] = []
        
    def validate_action(self, action: str, resource: str) -> Dict[str, Any]:
        """
        Validate whether an action is permitted by the intent.
        
        Returns:
            Dict with 'allowed' (bool), 'reason' (str), and 'timestamp'
        """
        timestamp = datetime.utcnow()
        
        # Check 1: Intent expired?
        if self.intent.is_expired():
            result = {
                'allowed': False,
                'reason': 'Intent has expired',
                'action': action,
                'resource': resource,
                'timestamp': timestamp.isoformat()
            }
            self.action_log.append(result)
            return result
        
        # Check 2: Resource explicitly forbidden?
        if self.intent.scope.is_forbidden(resource):
            result = {
                'allowed': False,
                'reason': f'Resource {resource} is explicitly forbidden by intent',
                'action': action,
                'resource': resource,
                'timestamp': timestamp.isoformat()
            }
            self.action_log.append(result)
            return result
        
        # Check 3: Resource in allowed scope?
        if not self.intent.scope.is_allowed(resource):
            result = {
                'allowed': False,
                'reason': f'Resource {resource} not in allowed scope',
                'action': action,
                'resource': resource,
                'timestamp': timestamp.isoformat()
            }
            self.action_log.append(result)
            return result
        
        # Check 4: Resource limits exceeded?
        if 'max_api_calls' in self.intent.scope.resource_limits:
            if len(self.action_log) >= self.intent.scope.resource_limits['max_api_calls']:
                result = {
                    'allowed': False,
                    'reason': 'Maximum API calls exceeded',
                    'action': action,
                    'resource': resource,
                    'timestamp': timestamp.isoformat()
                }
                self.action_log.append(result)
                return result
        
        # All checks passed
        result = {
            'allowed': True,
            'reason': 'Action aligns with declared intent',
            'action': action,
            'resource': resource,
            'timestamp': timestamp.isoformat()
        }
        self.action_log.append(result)
        return result
    
    def detect_drift(self, window_size: int = 10) -> Dict[str, Any]:
        """
        Analyze recent actions for drift from declared purpose.
        
        Drift detection looks for patterns indicating the agent is
        deviating from its stated purpose.
        """
        if len(self.action_log) < 3:
            return {'drift_detected': False, 'reason': 'Insufficient data'}
        
        recent_actions = self.action_log[-window_size:]
        
        # Check for repeated violations
        violations = [a for a in recent_actions if not a['allowed']]
        if len(violations) > 3:
            return {
                'drift_detected': True,
                'reason': 'Repeated violations detected',
                'violation_count': len(violations),
                'total_actions': len(recent_actions)
            }
        
        # Check for violation rate
        if len(violations) / len(recent_actions) > 0.3:
            return {
                'drift_detected': True,
                'reason': 'High violation rate',
                'violation_rate': len(violations) / len(recent_actions)
            }
        
        return {'drift_detected': False}
    
    def get_action_log(self) -> List[Dict[str, Any]]:
        """Return the complete action log for audit purposes."""
        return self.action_log.copy()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about actions taken under this intent."""
        total_actions = len(self.action_log)
        if total_actions == 0:
            return {
                'total_actions': 0,
                'allowed': 0,
                'blocked': 0,
                'violation_rate': 0.0
            }
        
        allowed = sum(1 for a in self.action_log if a['allowed'])
        blocked = total_actions - allowed
        
        return {
            'total_actions': total_actions,
            'allowed': allowed,
            'blocked': blocked,
            'violation_rate': blocked / total_actions if total_actions > 0 else 0.0,
            'intent_purpose': self.intent.declared_purpose,
            'is_expired': self.intent.is_expired()
        }


class IntentViolationError(Exception):
    """Raised when an action violates the declared intent."""
    pass


# Example usage and testing
if __name__ == "__main__":
    # Create a simple intent for scheduling a dentist appointment
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
    
    intent = IntentDeclaration(
        intent_id="booking-001",
        declared_purpose="Schedule dentist appointment for next Tuesday",
        authorized_by="user@example.com",
        scope=scope,
        success_criteria={
            "appointment_scheduled": True,
            "confirmation_sent": True
        }
    )
    
    print("Intent Declaration:")
    print(intent.to_json())
    print(f"\nIntent Hash: {intent.get_deterministic_hash()}")
    
    # Create validator
    validator = IntentValidator(intent)
    
    # Test legitimate action
    print("\n--- Testing Legitimate Action ---")
    result = validator.validate_action("search", "healthcare:search")
    print(f"Action: search healthcare:search")
    print(f"Allowed: {result['allowed']}")
    print(f"Reason: {result['reason']}")
    
    # Test forbidden action
    print("\n--- Testing Forbidden Action ---")
    result = validator.validate_action("read", "medical_records:patient_history")
    print(f"Action: read medical_records:patient_history")
    print(f"Allowed: {result['allowed']}")
    print(f"Reason: {result['reason']}")
    
    # Test unauthorized action
    print("\n--- Testing Unauthorized Action ---")
    result = validator.validate_action("modify", "payment:credit_card")
    print(f"Action: modify payment:credit_card")
    print(f"Allowed: {result['allowed']}")
    print(f"Reason: {result['reason']}")
    
    # Check statistics
    print("\n--- Statistics ---")
    stats = validator.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
