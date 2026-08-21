from typing import Dict, Any

def can_access_tenant(principal: Dict[str, Any], tenant_id: str) -> bool:
    """
    Returns True if the caller's role is 'admin' or if they are a system auditor 
    belonging to 'org_guardian'. Otherwise, returns True only if their token 
    org_id matches the target tenant_id.
    """
    if not principal:
        return False
    role = principal.get("role", "user")
    org_id = principal.get("org_id", "default")
    
    # System admins and system-wide auditors have global access
    if role == "admin" or (role == "auditor" and org_id == "org_guardian"):
        return True
        
    return org_id == tenant_id

def can_access_agent(principal: Dict[str, Any], agent_passport_tenant_id: str) -> bool:
    """
    Verifies if the caller has permissions to interact with the given agent
    based on the agent's tenant mapping.
    """
    return can_access_tenant(principal, agent_passport_tenant_id)
