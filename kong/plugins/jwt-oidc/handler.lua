local constants = require "kong.constants"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local kong_meta = require "kong.meta"

local socket = require "socket"
local issuer_keys = require("kong.plugins.jwt-oidc.issuer_keys")

local validate_audience = require("kong.plugins.jwt-oidc.validate_audience").validate_audience
local validate_issuer = require("kong.plugins.jwt-oidc.validate_issuer").validate_issuer
local validate_scope = require("kong.plugins.jwt-oidc.validate_scope").validate_scope

local re_gmatch = ngx.re.gmatch

local priority_env_var = "JWT_OIDC_PRIORITY"
local priority
if os.getenv(priority_env_var) then
    priority = tonumber(os.getenv(priority_env_var))
else
    priority = 1005
end
kong.log.debug('JWT_OIDC_PRIORITY: ' .. priority)

local JwtOidcHandler = {
  VERSION = kong_meta.version,
  PRIORITY = priority,
}

-------------------------------------------------------------------------------
-- custom helper function of the extended plugin "jwt-oidc"
-- (not contained in the official "jwt" pluging)
-------------------------------------------------------------------------------
local function custom_helper_table_to_string(tbl)
  local result = ""
  for k, v in pairs(tbl) do
      -- Check the key type (ignore any numerical keys - assume its an array)
      if type(k) == "string" then
          result = result.."[\""..k.."\"]".."="
      end

      -- Check the value type
      if type(v) == "table" then
          result = result..custom_helper_table_to_string(v)
      elseif type(v) == "boolean" then
          result = result..tostring(v)
      else
          result = result.."\""..v.."\""
      end
      result = result..","
  end
  -- Remove leading commas from the result
  if result ~= "" then
      result = result:sub(1, result:len()-1)
  end
  return result
end

-------------------------------------------------------------------------------
-- custom helper function of the extended plugin "jwt-oidc"
-- (not contained in the official "jwt" pluging)
-------------------------------------------------------------------------------
local function custom_helper_issuer_get_keys(jwks_uri_template, well_known_template, issuer, ssl_verify)
  local jwks_endpoint = issuer_keys.get_jwks_endpoint(jwks_uri_template, well_known_template, issuer, ssl_verify)
  kong.log.debug('Getting public keys from token issuer jwks_uri ' .. jwks_endpoint)
  local keys, err = issuer_keys.get_issuer_keys(jwks_endpoint, ssl_verify)
  if err then
      return nil, err
  end

  local decoded_keys = {}
  for i, key in ipairs(keys) do
      local decoded_key = jwt_decoder:base64_decode(key)
      if decoded_key ~= nil then
        decoded_keys[i] = decoded_key
      else
        decoded_keys[i] = key
      end
  end

  kong.log.debug('Number of keys retrieved: ' .. #decoded_keys)
  return {
      keys = decoded_keys,
      updated_at = socket.gettime(),
  }
end

-------------------------------------------------------------------------------
-- custom extension for the plugin "jwt-oidc"
-- (not contained in the official "jwt" pluging)
--
-- The extension of this plugin validates the token signature using the token
-- issuer public key. The issuer public key is fetched from the issuer's jwks_uri,
-- based on the base url from the "iss" claim from the token, using either the
-- configured jwks_uri_template or well_known_template.
-------------------------------------------------------------------------------
local function custom_validate_token_signature(conf, jwt, second_call)
  local issuer_cache_key = 'issuer_keys_' .. jwt.claims.iss

  -- Retrieve public keys
  local public_keys, err = kong.cache:get(issuer_cache_key, nil, custom_helper_issuer_get_keys, conf.jwks_uri_template, conf.well_known_template, jwt.claims.iss, conf.ssl_verify)

  if not public_keys then
      if err then
          kong.log.err(err)
      end
      return kong.response.exit(403, { message = "Unable to get public key for issuer" })
  end

  -- Verify signatures
  for _, k in ipairs(public_keys.keys) do
      if jwt:verify_signature(k) then
          kong.log.debug('JWT signature verified')
          return nil
      end
  end

  -- We could not validate signature, try to get a new keyset?
  local since_last_update = socket.gettime() - public_keys.updated_at
  if not second_call and since_last_update > conf.iss_key_grace_period then
      kong.log.debug('Could not validate signature. Keys updated last ' .. since_last_update .. ' seconds ago')
      -- can it be that the signature key of the issuer has changed ... ?
      -- invalidate the old keys in kong cache and do a current lookup to the signature keys
      -- of the token issuer
      kong.cache:invalidate_local(issuer_cache_key)
      return custom_validate_token_signature(conf, jwt, true)
  end

  return kong.response.exit(401, { message = "Invalid token signature" })
end

local function get_consumer_custom_id_cache_key(custom_id)
  return "custom_id_key_" .. custom_id
end

local function invalidate_customer(data)
  local customer = data.entity
  if data.operation == "update" then
    customer = data.old_entity
  end

  local key = get_consumer_custom_id_cache_key(customer.custom_id)
  kong.log.debug("invalidating customer " .. key)
  kong.cache:invalidate(key)
end

-- register at startup for events to be able to receive invalidate request needs
function JwtOidcHandler:init_worker()
  kong.worker_events.register(invalidate_customer, "crud", "consumers")
end


-------------------------------------------------------------------------------
-- Starting from here the "official" code of the community kong OSS version
-- plugin "jwt" is forked and in some places then extended with the special
-- logic from this plugin.
--
-- We use this ordering by intention that way .. if a new version of the
-- "jwt" plugin from kong is released .. these changes can me merged also
-- to this plugin here .... make the maintenance as easy as possible ...
--
-- This code is in sync with kong verion "3.7.1" jwt plugin as a baseline
-------------------------------------------------------------------------------


--- Retrieve a JWT in a request.
-- Checks for the JWT in URI parameters, then in cookies, and finally
-- in the configured header_names (defaults to `[Authorization]`).
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_tokens(conf)
  local token_set = {}
  local args = kong.request.get_query()
  for _, v in ipairs(conf.uri_param_names) do
    local token = args[v] -- can be a table
    if token then
      if type(token) == "table" then
        for _, t in ipairs(token) do
          if t ~= "" then
            token_set[t] = true
          end
        end

      elseif token ~= "" then
        token_set[token] = true
      end
    end
  end

  local var = ngx.var
  for _, v in ipairs(conf.cookie_names) do
    local cookie = var["cookie_" .. v]
    if cookie and cookie ~= "" then
      token_set[cookie] = true
    end
  end

  local request_headers = kong.request.get_headers()
  for _, v in ipairs(conf.header_names) do
    local token_header = request_headers[v]
    if token_header then
      if type(token_header) == "table" then
        token_header = token_header[1]
      end
      local iterator, iter_err = re_gmatch(token_header, "\\s*[Bb]earer\\s+(.+)")
      if not iterator then
        kong.log.err(iter_err)
        break
      end

      local m, err = iterator()
      if err then
        kong.log.err(err)
        break
      end

      if m and #m > 0 then
        if m[1] ~= "" then
          token_set[m[1]] = true
        end
      end
    end
  end

  local tokens_n = 0
  local tokens = {}
  for token, _ in pairs(token_set) do
    tokens_n = tokens_n + 1
    tokens[tokens_n] = token
  end

  if tokens_n == 0 then
    return nil
  end

  if tokens_n == 1 then
    return tokens[1]
  end

  return tokens
end

-------------------------------------------------------------------------------
-- function which also exist in original "jwt" kong OSS plugin
-- simplified to disregard credential and token
-------------------------------------------------------------------------------
local function set_consumer(consumer)
  local set_header = kong.service.request.set_header
  local clear_header = kong.service.request.clear_header

  if consumer and consumer.id then
    set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  else
    clear_header(constants.HEADERS.CONSUMER_ID)
  end

  if consumer and consumer.custom_id then
    kong.log.debug("found consumer " .. consumer.custom_id)
    set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  else
    clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
  end

  if consumer and consumer.username then
    set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  else
    clear_header(constants.HEADERS.CONSUMER_USERNAME)
  end

end

-------------------------------------------------------------------------------
-- custom extension for the plugin "jwt-oidc"
-- (not contained in the official "jwt" pluging)
--
-- The extension of this plugin provides the possibility to enforce "matching"
-- of consumer id from the token against the kong user object in the config
-- in a very configurable way.
-------------------------------------------------------------------------------
local function custom_load_consumer_by_custom_id(custom_id)
  local result, err = kong.db.consumers:select_by_custom_id(custom_id)
  if not result then
      return nil, err
  end
  return result
end

local function custom_match_consumer(conf, jwt)
  local consumer, err
  local consumer_id = jwt.claims[conf.consumer_match_claim]

  if conf.consumer_match_claim_custom_id then
      local consumer_cache_key = get_consumer_custom_id_cache_key(consumer_id)
      consumer, err = kong.cache:get(consumer_cache_key, nil, custom_load_consumer_by_custom_id, consumer_id, true)
  else
      local consumer_cache_key = kong.db.consumers:cache_key(consumer_id)
      consumer, err = kong.cache:get(consumer_cache_key, nil, kong.client.load_consumer, consumer_id, true)
  end

  if err then
      kong.log.err(err)
  end

  if not consumer and not conf.consumer_match_ignore_not_found then
      kong.log.debug("Unable to find consumer " .. consumer_id .." for token")
      return false, { status = 401, message = "Unable to find consumer " .. consumer_id .." for token" }
  end

  if consumer then
      set_consumer(consumer)
  end

  return true
end

-------------------------------------------------------------------------------
-- function which also exist in original "jwt" kong OSS plugin
-- simplified to disregard configured credential from consumer
-- extended to retrieve public key from issuer, and validate audience and scopes
-------------------------------------------------------------------------------

local function do_authentication(conf)
  local token, err = retrieve_tokens(conf)
  if err then
    kong.log.err(err)
    return kong.response.exit(500, { message = "An unexpected error occurred" })
  end

  local token_type = type(token)
  if token_type == "nil" then
    if conf.allow_anonymous then
      kong.service.request.set_header(constants.HEADERS.ANONYMOUS, true)
      return true
    else
      return false, { status = 401, message = "Unauthorized" }
    end
  elseif token_type ~= "string" then
    if token_type == "table" then
      return false, { status = 401, message = "Multiple tokens provided" }
    else
      return false, { status = 401, message = "Unrecognizable token" }
    end
  else
    kong.service.request.clear_header(constants.HEADERS.ANONYMOUS)
  end

  -- Decode token to find out who the consumer is
  local jwt, err = jwt_decoder:new(token)
  if err then
    return false, { status = 401, message = "Bad token; " .. tostring(err) }
  end

  local claims = jwt.claims
  local header = jwt.header

  -- Verify that the issuer is allowed
  if not validate_issuer(conf.allowed_iss, jwt.claims) then
    return false, { status = 401, message = "Token issuer not allowed" }
  end

  local algorithm = conf.algorithm or "HS256"

  -- Verify "alg"
  if jwt.header.alg ~= algorithm then
    return false, { status = 403, message = "Invalid algorithm" }
  end

  -- Now verify the JWT signature
  err = custom_validate_token_signature(conf, jwt)
  if err ~= nil then
    return false, err
  end

  -- Verify the JWT registered claims 'exp' and 'nbf'
  local ok, errors = jwt:verify_registered_claims(conf.claims_to_verify)
  if not ok then
    return false, { status = 401, message = "Token claims invalid: " .. custom_helper_table_to_string(errors) }
  end

  -- Verify maximum expiration
  if conf.maximum_expiration ~= nil and conf.maximum_expiration > 0 then
    local ok, errors = jwt:check_maximum_expiration(conf.maximum_expiration)
    if not ok then
      return false, { status = 403, message = "Token claims invalid: " .. custom_helper_table_to_string(errors) }
    end
  end

  -- Verify audience
  if conf.allowed_aud ~= nil and #conf.allowed_aud > 0 then
    local ok, err = validate_audience(conf.allowed_aud, jwt.claims)
    if not ok then
      return false, { status = 403, message = "Token claims invalid: " .. err }
    end
  end

  -- Verify scopes
  local ok, err = validate_scope(conf.scope, jwt.claims)
  if not ok then
    return false, { status = 403, message = "Access token does not have the required scope: " .. err }
  end

  -- Match consumer
  if conf.consumer_match then
    local ok, err = custom_match_consumer(conf, jwt)
    if not ok then
      return false, err
    end
  end

  -- Set upstream headers
  if conf.upstream_claim_headers ~= nil and #conf.upstream_claim_headers > 0 then
    for _, claim_name in ipairs(conf.upstream_claim_headers) do
      local claim_value = jwt.claims[claim_name]
      if claim_value and claim_value ~= "" then
        kong.service.request.set_header(conf.upstream_claim_header_prefix .. claim_name, claim_value)
      end
    end
  end

  -- Set upstream shared context
  kong.ctx.shared.jwt_oidc_token = jwt
  return true

end


function JwtOidcHandler:access(conf)
  -- check if preflight request and whether it should be authenticated
  if not conf.run_on_preflight and kong.request.get_method() == "OPTIONS" then
    return
  end

  local ok, err = do_authentication(conf)
  if not ok then
    return kong.response.exit(err.status, err.errors or { message = err.message })
  end
end


return JwtOidcHandler
