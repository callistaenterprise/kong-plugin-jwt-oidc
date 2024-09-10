local cjson_safe = require "cjson.safe"
local x509 = require "resty.openssl.x509"
local httpc = require("resty.http")

local function get_jwks_endpoint(jwks_uri_template, well_known_template, issuer, ssl_verify)
    if jwks_uri_template ~= nil then
        return string.format(jwks_uri_template, issuer)
    end

    local wellknown_endpoint = string.format(well_known_template, issuer)
    kong.log.debug('Getting jwks_uri from wellknown_endpoint ', wellknown_endpoint)

    local res, err = httpc.new():request_uri(wellknown_endpoint, {method = "GET", ssl_verify = ssl_verify})
    if not res then
        return nil, err
    end
    local body = cjson_safe.decode(res.body)
    return body['jwks_uri']
end

local function get_public_key(pem)
    local cert = x509.new(pem)
    return cert:get_pubkey():tostring()
end

local function get_issuer_keys(jwks_endpoint, ssl_verify)
    local res, err = httpc.new():request_uri(jwks_endpoint, {method = "GET", ssl_verify = ssl_verify})
    if not res then
        return nil, err
    end
    local body = cjson_safe.decode(res.body)

    local keys = {}
    for i, key in ipairs(body['keys']) do
        local cert = "-----BEGIN CERTIFICATE-----\n" .. key.x5c[1] .. "\n-----END CERTIFICATE-----"
        keys[i] = get_public_key(cert)
    end
    return keys, nil
end

return {
    get_request = get_request,
    get_issuer_keys = get_issuer_keys,
    get_jwks_endpoint = get_jwks_endpoint,
}
