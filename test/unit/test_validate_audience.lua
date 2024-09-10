local lu = require("luaunit")
local validate_audience = require("kong.plugins.jwt-oidc.validate_audience").validate_audience

local TestValidateAudience = {}

local test_claims = {
    aud = "test-audience"
}

function TestValidateAudience:test_nil_claims()
    local valid, err = validate_audience({"test-audience"}, nil)
    lu.assertNil(valid)
    lu.assertEquals("Missing audience claim", err)
end

function TestValidateAudience:test_missing_claim()
    local valid, err = validate_audience({"test-audience"}, {})
    lu.assertNil(valid)
    lu.assertEquals("Missing audience claim", err)
end

function TestValidateAudience:test_valid_audience()
    local valid, err = validate_audience({"test-audience"}, test_claims)
    lu.assertTrue(valid)
end

function TestValidateAudience:test_invalid_audience()
    local valid, err = validate_audience({"production-audience"}, test_claims)
    lu.assertNil(valid)
    lu.assertEquals("Token audience not allowed", err)
end

function TestValidateAudience:test_multiple_audiences()
    local valid, err = validate_audience({"production-audience", "test-audience"}, test_claims)
    lu.assertTrue(valid)
end

function TestValidateAudience:test_partial_audience_match()
    local valid, err = validate_audience({"audience"}, test_claims)
    lu.assertNil(valid)
    lu.assertEquals("Token audience not allowed", err)
end

return TestValidateAudience