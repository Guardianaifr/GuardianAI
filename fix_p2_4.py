with open('backend/routers/scan_routes.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_route = '''@router.get("/api/v1/leaderboard", tags=["Audit Scanner"])
def get_leaderboard(limit: int = 50):'''

new_route = '''@router.get("/api/v1/leaderboard", tags=["Audit Scanner"])
def get_leaderboard(limit: int = 50, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):'''

content = content.replace(old_route, new_route)

with open('backend/routers/scan_routes.py', 'w', encoding='utf-8') as f:
    f.write(content)
