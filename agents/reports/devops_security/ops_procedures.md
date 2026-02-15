# GuardianAI Operational Procedures

## Startup
1. Start mock agent: `python mock_openclaw_agent.py`
2. Start guardian proxy: `python guardian/main.py`
3. Start backend dashboard: `python backend/main.py`

## Monitoring
- Check dashboard at http://localhost:8001
- Monitor memory usage via `psutil`

## Backup
- SQLite DB at `guardian.db` and `backend/guardian.db`
- Daily backup recommended

## Incident Response
1. Check logs in sim_log.txt
2. Review guardian proxy stderr output
3. Restart services if needed