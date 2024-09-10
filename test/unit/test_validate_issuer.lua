local lu = require("luaunit")
local validate_issuer = require("kong.plugins.jwt-oidc.validate_issuer").validate_issuer

local TestValidateIssuer = {}

local test_claims = {
    iss = "http://keycloak-headless/auth/realms/master"
}

function TestValidateIssuer:test_nil_issuers()
    local valid, err = validate_issuer(nil, "")
    lu.assertNil(valid)
    lu.assertEquals("Allowed issuers is empty", err)
end

function TestValidateIssuer:test_empty_issuers()
    local valid, err = validate_issuer({}, "")
    lu.assertNil(valid)
    lu.assertEquals("Allowed issuers is empty", err)
end

function TestValidateIssuer:test_iss_claim_missing()
    local valid, err = validate_issuer(
        {"http://keycloak-headless/auth/realms/master"}, 
        {}
    )
    lu.assertNil(valid)
    lu.assertEquals("Missing issuer claim", err)
end

function TestValidateIssuer:test_single_valid_issuer()
    local valid, err = validate_issuer(
        {"http://keycloak-headless/auth/realms/master"}, 
        test_claims
    )
    lu.assertTrue(valid)
end

function TestValidateIssuer:test_invalid_issuer()
    local valid, err = validate_issuer(
        {"http://localhost:8080/auth/realms/master"}, 
        test_claims
    )
    lu.assertNil(valid)
    lu.assertEquals("Token issuer not allowed", err)
end

function TestValidateIssuer:test_multiple_valid_issuers()
    local valid, err = validate_issuer({
        "http://keycloak-headless/auth/realms/master",
        "http://localhost:8080/auth/realms/master"
    }, 
        test_claims
    )
    lu.assertTrue(valid)
end

function TestValidateIssuer:test_matching_issuer()
    local valid, err = validate_issuer(
        {"http://keycloak%-headless/auth/realms/.+"}, 
        test_claims
    )
    lu.assertTrue(valid)
end

return TestValidateIssuer
