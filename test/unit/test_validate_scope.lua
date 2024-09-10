local lu = require("luaunit")
local validate_scope = require("kong.plugins.jwt-oidc.validate_scope").validate_scope

local TestValidateScope = {}

local test_claims = {
    scope = "profile email dashed-scope"
}

function TestValidateScope:test_nil_scopes()
    local valid, err = validate_scope(nil, test_claims)
    lu.assertTrue(valid)
end

function TestValidateScope:test_allowed_scopes_empty_list()
    local valid, err = validate_scope({}, test_claims)
    lu.assertTrue(valid)
end

function TestValidateScope:test_jwt_claims_nil()
    local valid, err = validate_scope({"profile"}, nil)
    lu.assertNil(valid)
    lu.assertEquals("Missing required scope claim", err)
end

function TestValidateScope:test_scope_claim_nil()
    local valid, err = validate_scope({"profile"}, {})
    lu.assertNil(valid)
    lu.assertEquals("Missing required scope claim", err)
end

function TestValidateScope:test_valid_scope()
    local valid, err = validate_scope({"profile"}, test_claims)
    lu.assertTrue(valid)
end

function TestValidateScope:test_invalid_scope()
    local valid, err = validate_scope({"account"}, test_claims)
    lu.assertNil(valid)
    lu.assertEquals("Missing required scope", err)
end

function TestValidateScope:test_multiple_scopes()
    local valid, err = validate_scope({"account", "email"}, test_claims)
    lu.assertTrue(valid)
end

function TestValidateScope:test_pattern_chars_in_scope()
    local valid, err = validate_scope({"dashed-scope"}, test_claims)
    lu.assertTrue(valid)
end

function TestValidateScope:test_partial_scope_match()
    local valid, err = validate_scope({"dashed"}, test_claims)
    lu.assertNil(valid)
    lu.assertEquals("Missing required scope", err)
end

return TestValidateScope
