local plugin_name = "jwt-oidc"
local package_name = "kong-plugin-" .. plugin_name
local package_version = "1.0.0"
local rockspec_revision = "0"

package = package_name
version = package_version .. "-" .. rockspec_revision
supported_platforms = { "linux", "macosx" }

source = {
  url = "git://github.com/callistaenterprise/kong-plugin-jwt-oidc",
  tag = "1.0.0",
  dir = "kong-plugin-jwt-oidc"
}

description = {
  summary = "A Kong plugin that will validate tokens issued by an OIDC issuer",
   homepage = "https://github.com/callistaenterprise/kong-plugin-jwt-oidc",
  license = "Apache 2.0",
}


dependencies = {
  "lua ~> 5"
}

test_dependencies = {
  "luaunit >= 3.4"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins."..plugin_name..".handler"]            = "kong/plugins/"..plugin_name.."/handler.lua",
    ["kong.plugins."..plugin_name..".schema"]             = "kong/plugins/"..plugin_name.."/schema.lua",
    ["kong.plugins."..plugin_name..".issuer_keys"]        = "kong/plugins/"..plugin_name.."/issuer_keys.lua",
    ["kong.plugins."..plugin_name..".validate_audience"] = "kong/plugins/"..plugin_name.."/validate_audience.lua",
    ["kong.plugins."..plugin_name..".validate_issuer"]   = "kong/plugins/"..plugin_name.."/validate_issuer.lua",
    ["kong.plugins."..plugin_name..".validate_scope"]    = "kong/plugins/"..plugin_name.."/validate_scope.lua",
  }
}

test = {
  type = "command",
  command = "lua test/unit/test_suite.lua -o TAP"
}
