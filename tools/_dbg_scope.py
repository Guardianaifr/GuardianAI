scopes = [
    "telemetry\x00", "tele\x0ametry", "events;admin", "admin|events",
    'te"lemetry', "admin' OR '1'='1", "events/*",
    "../../../admin", "admin\r\n", "<script>admin</script>",
]
valid = {"telemetry", "events", "admin"}
for s in scopes:
    cleaned = s.strip().lower()
    if cleaned in valid:
        print(f"ACCEPTED: {repr(s)} -> {repr(cleaned)}")
    else:
        print(f"REJECTED: {repr(s)} -> {repr(cleaned)}")
