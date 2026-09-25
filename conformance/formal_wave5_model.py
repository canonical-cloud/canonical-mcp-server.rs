from itertools import product


def admitted(authenticated: bool, tenant_match: bool, mutating: bool, admin: bool) -> bool:
    return authenticated and tenant_match and (not mutating or admin)


for authenticated, tenant_match, mutating, admin in product((False, True), repeat=4):
    allowed = admitted(authenticated, tenant_match, mutating, admin)
    if allowed:
        assert authenticated and tenant_match
        if mutating:
            assert admin

assert admitted(True, True, False, False)
assert not admitted(True, True, True, False)
assert not admitted(True, False, False, True)
print('formal_wave5_model: ok')
