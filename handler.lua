local http = require "resty.http"
local cjson = require "cjson"

local TokenHandler = {
    VERSION = "1.2",
    PRIORITY = -1,
}

local function introspect_access_token(conf, access_token, req_uri, headers)
    local httpc = http:new()

    kong.log.info('oauth2-custom authorization', '{ "uri":"' .. req_uri .. '"}')

    headers = headers or {}
    headers["Content-Type"] = "application/json"
    headers["Authorization"] = "Bearer " .. access_token

    local res, err = httpc:request_uri(conf.authorization_endpoint, {
        method = "POST",
        ssl_verify = false,
        body = '{"uri":"' .. req_uri .. '"}',
        headers = headers
    })

    if not res then
        kong.log.err("failed to call authorization endpoint: ", err)
        return kong.response.exit(500, { message = "Internal Server Error" })
    end

    if res.status ~= 200 then
        kong.log.err("authorization endpoint responded with status: ", res.status)
        kong.log.debug("response body: ", res.body)
        return kong.response.exit(res.status, { message = "Authorization Failed" })
    end

    -- Assuming the response data is in JSON format
    local data = cjson.decode(res.body)
    if not data then
        return kong.response.exit(500, { message = "Invalid JSON response from authorization endpoint" })
    end
    return data  -- returning the decoded data
end

function TokenHandler:access(conf)
    if not conf.authorization_endpoint or not conf.token_header or not conf.user_id_header then
        return kong.response.exit(500, { message = "Missing required configuration" })
    end
    
    local access_token = kong.request.get_headers()[conf.token_header]
    if not access_token then
        return kong.response.exit(401, { message = "Unauthorized" })
    end

    -- Replace Bearer prefix
    local bearer_prefix = "Bearer "
    if not access_token:find(bearer_prefix, 1, true) then
        return kong.response.exit(401, { message = "Invalid or missing Bearer token" })
    end
    access_token = access_token:sub(#bearer_prefix + 1) -- drop "Bearer "
    -- access_token = access_token:sub(8, -1) -- drop "Bearer "
    
    local request_path = kong.request.get_path() -- get path

    local headers = {
        ["x-b3-traceid"] = ngx.var.http_x_b3_traceid or "",
        ["x-b3-spanid"] = ngx.var.http_x_b3_spanid or "",
        ["x-b3-sampled"] = ngx.var.http_x_b3_sampled or "",
    }
    
    local response_data = introspect_access_token(conf, access_token, request_path, headers)

    -- Forward the 'X-User-Id' header to the upstream service
    if response_data and response_data.data and response_data.data.userName then
        kong.service.request.set_header(conf.user_id_header, response_data.data.userName)
    end

    -- Clear the "Authorization" header before forwarding to the upstream service
    kong.service.request.clear_header(conf.token_header)
end

-- No header_filter function is needed in this case

return TokenHandler
