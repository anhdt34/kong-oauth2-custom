local http = require "resty.http"
local cjson = require "cjson"
-- local opentelemetry = require "opentelemetry"

local TokenHandler = {
    VERSION = "1.2.2",
    PRIORITY = -1,
}

local function introspect_access_token(conf, access_token, req_uri)
    local httpc = http:new()

    local headers = {
        ["Content-Type"] = "application/json",
        ["Authorization"] = "Bearer " .. access_token,
        ["traceparent"] = kong.request.get_header("traceparent") or "",
    }

    -- Inject trace context into headers
    -- local current_context = opentelemetry.get_text_map_propagator():inject(opentelemetry.get_context(), headers)

    local res, err = httpc:request_uri(conf.authorization_endpoint, {
        method = "POST",
        ssl_verify = false,
        body = '{"uri":"' .. req_uri .. '"}',
        headers = headers
    })

    if not res then
        kong.log.err("failed to call authorization endpoint: ", err)
        return kong.response.exit(500, 
        {
            response = {
                message = {
                    language = "en",
                    content = "Internal Server Error"
                },
                version = "1.2.2",
                code = "000_05"
            },
            signature = ""
        })
    end

    if res.status ~= 200 then
        kong.log.err("authorization endpoint responded with status: ", res.status)
        kong.log.debug("response body: ", res.body)
        return kong.response.exit(res.status, cjson.decode(res.body))
    end

    -- Assuming the response data is in JSON format
    local data = cjson.decode(res.body)
    if not data then
        return kong.response.exit(500, 
        {
            response = {
                message = {
                    language = "en",
                    content = "Invalid JSON response from authorization endpoint"
                },
                version = "1.2.2",
                code = "000_04"
            },
            signature = ""
        })
    end
    return data  -- returning the decoded data
end

function TokenHandler:access(conf)
    if not conf.authorization_endpoint or not conf.token_header or not conf.user_id_header then
        return kong.response.exit(500, 
        {
            response = {
                message = {
                    language = "en",
                    content = "Missing required configuration"
                },
                version = "1.2.2",
                code = "000_01"
            },
            signature = ""
        })
    end
    
    local access_token = kong.request.get_headers()[conf.token_header]
    if not access_token then
        return kong.response.exit(401, 
        {
            response = {
                message = {
                    language = "en",
                    content = "Missing token"
                },
                version = "1.2.2",
                code = "000_02"
            },
            signature = ""
        })
    end

    -- Replace Bearer prefix
    local bearer_prefix = "Bearer "
    if not access_token:find(bearer_prefix, 1, true) then
        return kong.response.exit(401, 
        {
            response = {
                message = {
                    language = "en",
                    content = "Invalid or missing Bearer token"
                },
                version = "1.2.2",
                code = "000_03"
            },
            signature = ""
        })
    end
    access_token = access_token:sub(#bearer_prefix + 1) -- drop "Bearer "
    
    local request_path = kong.request.get_path() -- get path

    local response_data = introspect_access_token(conf, access_token, request_path)

    -- Forward the 'X-User-Id' header to the upstream service
    if response_data and response_data.data and response_data.data.userName then
        kong.service.request.set_header(conf.user_id_header, response_data.data.userName)
    end

    -- Clear the "Authorization" header before forwarding to the upstream service
    kong.service.request.clear_header(conf.token_header)
end

-- No header_filter function is needed in this case

return TokenHandler
