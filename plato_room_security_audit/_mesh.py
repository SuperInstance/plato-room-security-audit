"""
Mesh registration for PLATO plugin discovery.
"""

def register(registry):
    """Register the security audit room with the PLATO mesh."""
    from .room import SecurityAuditRoom

    registry.register("rooms", "security_audit", lambda: SecurityAuditRoom)
