"""make_cr() from RuleGate's conftest (@ 6ce533b), for the ported review tests."""


def make_cr(vendor="panos", **request):
    from agenttrustsec.review.models.change_request import NormalizedChangeRequest

    base = {
        "panos": dict(source_zone="web-dmz", source=["10.20.30.0/27"], destination_zone="db-trust",
                      destination=["10.40.10.15"], application=["postgres"], service=["tcp/5432"],
                      security_profile_group="Strict-Inspection"),
        "ftd": dict(source_zone="inside", source=["10.10.0.0/24"], destination_zone="dc",
                    destination=["10.60.2.30"], service=["tcp/8443"],
                    intrusion_policy="Balanced Security and Connectivity"),
    }[vendor]
    base.update(request)
    meta = {k: base.pop(k) for k in ("temporary", "expiry", "ticket_ref", "business_justification", "requester") if k in base}
    return NormalizedChangeRequest.model_validate({
        "change_id": "CR-TEST",
        "ticket_ref": meta.get("ticket_ref", "CHG0000001"),
        "requester": meta.get("requester", "tester"),
        "business_justification": meta.get("business_justification", "Unit test business justification"),
        "target": {"vendor": vendor, "device_group": "DC-Core" if vendor == "panos" else "DC-Edge-ACP"},
        "request": base,
        "temporary": meta.get("temporary", False),
        "expiry": meta.get("expiry"),
    })
