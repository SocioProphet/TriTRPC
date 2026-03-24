from tritrpc_requirements_impl.audit import AuditRecord, append_audit_record, verify_audit_chain



def test_audit_chain_detects_tamper() -> None:
    chain = []
    r1 = AuditRecord(sequence=1, timestamp="2026-03-11T03:01:00Z", event_type="config-apply", decision="allow", suite="FIPS_CLASSICAL")
    r1 = append_audit_record(chain, r1)
    chain.append(r1)
    r2 = AuditRecord(sequence=2, timestamp="2026-03-11T03:02:00Z", event_type="frame-emit", decision="allow", suite="FIPS_CLASSICAL")
    r2 = append_audit_record(chain, r2)
    chain.append(r2)
    assert verify_audit_chain(chain)
    tampered = [chain[0], AuditRecord(**{**chain[1].__dict__, "decision": "deny"})]
    assert not verify_audit_chain(tampered)
