# Ported from RuleGate tests (crewai_fw_chg_reviewer @ 6ce533b): proves the vendored core is faithful.
from review_helpers import make_cr

from agenttrustsec.review.analysis import address_math as am
from agenttrustsec.review.analysis.shadow import analyze
from agenttrustsec.review.models.normalized_rule import NormalizedRule


def rule(pos, name, action="allow", layer="pre", src="any", dst="any", svc="any", zones=("any", "any"),
         vendor="panos", **kw):
    resolver = am.ObjectResolver({})
    return NormalizedRule(
        vendor=vendor, rule_id=name, name=name, position=pos, layer=layer, action=action,
        src_zones=[zones[0]], dst_zones=[zones[1]],
        src_addrs=resolver.resolve(src), dst_addrs=resolver.resolve(dst),
        services=am.parse_service_token(svc), **kw)


CLEANUP = rule(99, "cleanup", action="deny", layer="post")


def test_duplicate_when_broader_allow_matches_first():
    rules = [rule(1, "broad", src="10.0.0.0/8", dst="10.0.0.0/8", svc="tcp/5432"), CLEANUP]
    rep = analyze(make_cr(application=["any"]), rules)
    assert rep.duplicate_of.name == "broad"


def test_not_duplicate_if_deny_partially_overlaps_first():
    rules = [rule(1, "partial-deny", action="deny", src="10.20.30.0/28", svc="tcp/5432"),
             rule(2, "broad", src="10.0.0.0/8", dst="10.0.0.0/8", svc="tcp/5432"), CLEANUP]
    rep = analyze(make_cr(application=["any"]), rules)
    assert rep.duplicate_of is None


def test_app_scoped_rule_does_not_cover_app_any_request():
    rules = [rule(1, "pg-only", src="10.0.0.0/8", dst="10.0.0.0/8", svc="tcp/5432", applications=["postgres"]),
             CLEANUP]
    rep = analyze(make_cr(application=["any"]), rules)
    assert rep.duplicate_of is None
    assert rep.partial_overlaps[0].partial_dimensions == ["applications"]


def test_shadowed_by_deny_above_placement():
    rules = [rule(1, "deny-db", action="deny", zones=("web-dmz", "db-trust")), CLEANUP]
    rep = analyze(make_cr(placement="bottom"), rules)
    assert rep.shadowed_by.name == "deny-db"
    assert rep.deny_overrides == []


def test_deny_override_when_placed_above_explicit_deny():
    rules = [rule(1, "deny-db", action="deny", zones=("web-dmz", "db-trust")), CLEANUP]
    rep = analyze(make_cr(placement="top"), rules)
    assert [d.name for d in rep.deny_overrides] == ["deny-db"]
    assert rep.shadowed_by is None


def test_catch_all_deny_is_not_an_override():
    rep = analyze(make_cr(placement="top"), [CLEANUP])
    assert rep.deny_overrides == [] and rep.partial_overlaps == []


def test_disabled_rules_are_cleanup_candidates_only():
    rules = [rule(1, "old", src="10.0.0.0/8", dst="10.0.0.0/8", enabled=False), CLEANUP]
    rep = analyze(make_cr(application=["any"]), rules)
    assert rep.duplicate_of is None
    assert [r.name for r in rep.disabled_cleanup_candidates] == ["old"]


def test_unresolved_rule_needs_review_not_duplicate():
    rules = [rule(1, "fqdn-rule", dst="db.example.net"), CLEANUP]
    rep = analyze(make_cr(application=["any"]), rules)
    assert rep.duplicate_of is None
    assert rep.needs_review and rep.needs_review[0].rule.name == "fqdn-rule"


def test_user_based_rule_needs_review():
    rules = [rule(1, "users", users=["corp\\dba"]), CLEANUP]
    rep = analyze(make_cr(application=["any"]), rules)
    assert rep.duplicate_of is None and rep.needs_human_review


def test_partial_overlap_lists_dimensions():
    rules = [rule(1, "narrow", src="10.20.30.0/28", dst="10.40.10.15", svc="tcp/5432",
                  zones=("web-dmz", "db-trust")), CLEANUP]
    rep = analyze(make_cr(application=["any"]), rules)
    assert rep.partial_overlaps[0].partial_dimensions == ["src_addrs"]


def test_placement_before_named_rule():
    rules = [rule(1, "a", zones=("x", "y")), rule(2, "b", zones=("x", "y")), CLEANUP]
    rep = analyze(make_cr(placement="before:b"), rules)
    assert rep.insertion_position == 2 and rep.move_before == "b"


def test_unknown_placement_reference_falls_back_with_note():
    rep = analyze(make_cr(placement="after:missing"), [CLEANUP])
    assert rep.placement_notes and "not found" in rep.placement_notes[0]


def test_ftd_prefilter_fastpath_evaluated_before_acp():
    fp = rule(1, "fp", action="fastpath", layer="prefilter", src="10.10.0.0/16", dst="10.60.0.0/16",
              zones=("inside", "dc"), vendor="ftd")
    deny = rule(2, "acp-deny", action="deny", layer="mandatory", zones=("inside", "dc"), vendor="ftd")
    rep = analyze(make_cr("ftd"), [fp, deny])
    assert rep.section == "mandatory"
    assert rep.duplicate_of.name == "fp"   # Fastpath already permits; the ACP deny never sees this traffic
    assert rep.shadowed_by is None         # the covering rule above is a permit, not an opposite action


def test_ftd_monitor_rules_do_not_terminate():
    mon = rule(1, "monitor-all", action="monitor", layer="mandatory", vendor="ftd")
    allow = rule(2, "allow", layer="mandatory", src="10.10.0.0/16", dst="10.60.0.0/16", zones=("inside", "dc"),
                 vendor="ftd")
    rep = analyze(make_cr("ftd"), [mon, allow])
    assert rep.duplicate_of.name == "allow"
