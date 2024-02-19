local http = require "resty.http"
local cjson = require "cjson"  -- Assuming you have the cjson module installed

local TokenHandler = {
    VERSION = "1.0",
    PRIORITY = 100,
}

local function introspect_access_token(conf, access_token, req_uri)
    local httpc = http:new()

    kong.log.info('oauth2-custom authorization', '{ "uri":"' .. req_uri .. '"}')

    local res, err = httpc:request_uri(conf.authorization_endpoint, {
        method = "POST",
        ssl_verify = false,
        body = '{"uri":"' .. req_uri .. '"}',
        headers = {
            ["Content-Type"] = "application/json",
            ["Authorization"] = "Bearer " .. access_token
        }
    })

    if not res then
        kong.log.err("failed to call authorization endpoint: ", err)
        return kong.response.exit(500)
    end

    if res.status ~= 200 then
        kong.log.err("authorization endpoint responded with status: ", res.status)
        return kong.response.exit(500)
    end

    -- Assuming the response data is in JSON format
    local data = cjson.decode(res.body)
    return data  -- returning the decoded data
end

function TokenHandler:access(conf)
    local access_token = kong.request.get_headers()[conf.token_header]

    if not access_token then
        kong.response.exit(401)  -- unauthorized
    end

    -- Replace Bearer prefix
    access_token = access_token:sub(8, -1) -- drop "Bearer "
    local request_path = kong.request.get_path()

    local response_data = introspect_access_token(conf, access_token, request_path)

    -- Save the response data in the ngx.ctx table to access it in the header_filter phase
    ngx.ctx.response_data = response_data
end

function TokenHandler:header_filter(conf)
    -- Check if response_data is available in the ngx.ctx table
    local response_data = ngx.ctx.response_data

    if response_data then
        local user_id = response_data.userName

        if user_id then
            kong.response.add_header("X-User-Id", user_id)
        end
    end

    -- Clear the "Authorization" header
    kong.response.clear_header("Authorization")
end

return TokenHandler
