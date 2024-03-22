local http = require "resty.http"
local cjson = require "cjson"

local TokenHandler = {
    VERSION = "1.2.2",
    PRIORITY = -1,
}

local function create_response(code, message_content)
    return {
        response = {
            message = {
                language = "en",
                content = message_content
            },
            version = TokenHandler.VERSION,
            code = code
        },
        signature = ""
    }
end

local function call_authorization_endpoint(conf, access_token, req_uri)
    local httpc = http.new()

    local headers = {
        ["Content-Type"] = "application/json",
        ["Authorization"] = "Bearer " .. access_token,
        ["traceparent"] = kong.request.get_header("traceparent") or "",
    }

    local res, err = httpc:request_uri(conf.authorization_endpoint, {
        method = "POST",
        ssl_verify = false,
        body = cjson.encode({ uri = req_uri }), -- Encode request body
        headers = headers
    })

    if not res then
        return kong.response.exit(500, create_response("000_05", "Internal Server Error"))
    end

    if res.status ~= 200 then
        kong.log.err("Authorization endpoint responded with status: ", res.status)
        kong.log.debug("Response body: ", res.body)
        return kong.response.exit(res.status, cjson.decode(res.body))
    end

    local data, decode_err = cjson.decode(res.body)
    if not data then
        return kong.response.exit(500, create_response("000_04", "Invalid JSON response from authorization endpoint"))
    end

    return data
end

function TokenHandler:access(conf)
    if not conf.authorization_endpoint or not conf.token_header or not conf.user_id_header then
        return kong.response.exit(500, create_response("000_01", "Missing required configuration"))
    end
    
    local access_token = kong.request.get_headers()[conf.token_header]
    if not access_token then
        return kong.response.exit(401, create_response("000_02", "Missing token"))
    end

    -- Check and remove Bearer prefix
    local bearer_prefix = "Bearer "
    if not access_token:find(bearer_prefix, 1, true) then
        return kong.response.exit(401, create_response("000_03", "Invalid or missing Bearer token"))
    end
    access_token = access_token:sub(#bearer_prefix + 1) -- Remove "Bearer "
    
    local request_path = kong.request.get_path()

    local response_data = call_authorization_endpoint(conf, access_token, request_path)

    if response_data and response_data.data and response_data.data.userName then
        kong.service.request.set_header(conf.user_id_header, response_data.data.userName)
    end

    -- Clear the "Authorization" header before forwarding to the upstream service
    kong.service.request.clear_header(conf.token_header)
end

return TokenHandler
