import pytest

from agenttrustsec.authz.tbac import PolicyError, TbacPolicy
from agenttrustsec.models import Status


def test_allowed(policy):
    assert policy.check("reader", "show_acl").status is Status.PASS


def test_role_not_allowed(policy):
    assert policy.check("reader", "push_config").status is Status.FAIL


def test_unknown_tool_denied(policy):
    assert policy.check("executor", "factory_reset").status is Status.FAIL


def test_unknown_role_denied(policy):
    assert policy.check("admin", "show_acl").status is Status.FAIL


def test_only_executor_has_change_tools(policy):
    for spec in policy.tools.values():
        if spec.change:
            assert spec.allowed_roles == {"executor"}


@pytest.mark.parametrize("wild", ["*", "any", "all"])
def test_wildcard_rejected(tmp_path, wild):
    p = tmp_path / "bad.yaml"
    p.write_text(f"tools:\n  x:\n    change: false\n    allowed_roles: ['{wild}']\n")
    with pytest.raises(PolicyError, match="wildcard"):
        TbacPolicy.from_yaml(p)


def test_change_flag_required(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("tools:\n  x:\n    allowed_roles: [reader]\n")
    with pytest.raises(PolicyError, match="change"):
        TbacPolicy.from_yaml(p)
