local function validate_audience(allowed_audience, jwt_claims)
    if jwt_claims == nil or jwt_claims.aud == nil then
        return nil, "Missing audience claim"
    end
    for _, curr_aud in pairs(allowed_audience) do
        if curr_aud == jwt_claims.aud then
            return true
        end
    end
    return nil, "Token audience not allowed"
end

return {
    validate_audience = validate_audience
}
