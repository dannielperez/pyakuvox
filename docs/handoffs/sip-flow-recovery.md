# sip-flow-recovery

Added bounded allowlisted SIP inspection and idle-only UDP port renewal. Tests cover busy/unknown calls, identity, reserved ports, TCP refusal, retry prohibition, registration failure, ambiguous write and concurrent-change rollback. Run `pytest tests/test_sip_recovery.py --import-mode=importlib`; 11 tests pass. No live firmware call performed. Consumer must serialize device mutations and independently verify PBX reachability; canary firmware validation remains required.
