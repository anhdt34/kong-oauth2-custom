local http = require "resty.http"
local utils = require "kong.tools.utils"

local TokenHandler = {
    VERSION = "1.0",
    PRIORITY = 1000,
}


local function introspect_access_token(conf, access_token, req_uri)
  local httpc = http:new()
  -- step 1: validate the token
  kong.log.info('oauth2-custom authentication', '{"uri":"' .. req_uri .. '"}')
  local res, err = httpc:request_uri(conf.authentication_endpoint, {
      method = "POST",
      ssl_verify = false,
      headers = {
          ["Content-Type"] = "application/x-www-form-urlencoded",
          ["Authorization"] = "Bearer " .. access_token }
  })

  if not res then
      kong.log.err("failed to call authentication endpoint: ",err)
      return kong.response.exit(500)
  end
  if res.status ~= 200 then
      kong.log.err("authentication endpoint responded with status: ",res.status)
      return kong.response.exit(500)
  end

  -- step 2: validate the customer access rights
  kong.log.info('oauth2-custom authorization', '{ "uri":"' .. req_uri .. '"}')
  local res, _ = httpc:request_uri(conf.authorization_endpoint, {
      method = "POST",
      ssl_verify = false,
      body = '{"uri":"' .. req_uri .. '"}',
      headers = { ["Content-Type"] = "application/json",
          ["Authorization"] = "Bearer " .. access_token }
  })

  if not res then
    kong.log.err("failed to call authorization endpoint: ",err)
    return kong.response.exit(500)
  end
  if res.status ~= 200 then
      kong.log.err("authorization endpoint responded with status: ",res.status)
      return kong.response.exit(500)
  end

  return true -- all is well
end

function TokenHandler:access(conf)
  local access_token = kong.request.get_headers()[conf.token_header]
  if not access_token then
      kong.response.exit(401)  --unauthorized
  end
  -- replace Bearer prefix
  access_token = access_token:sub(8,-1) -- drop "Bearer "
  local request_path = kong.request.get_path()

  introspect_access_token(conf, access_token, request_path)

  kong.service.clear_header(conf.token_header)
end


return TokenHandler
