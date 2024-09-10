TestValidateAudience = require("test/unit/test_validate_audience")
TestValidateIssuer = require("test/unit/test_validate_issuer")
TestValidateScope = require("test/unit/test_validate_scope")

local lu = require("luaunit")
os.exit(lu.LuaUnit.run())
