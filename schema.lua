local typedefs = require "kong.db.schema.typedefs"

return {
  name = "kong-oauth2-custom",
  fields = {
    { protocols = typedefs.protocols_http },
    { consumer = typedefs.no_consumer },
    { config = {
        type = "record",
        fields = {
          { authorization_endpoint = typedefs.url({ required = true }) },
          { token_header = typedefs.header_name { default = "Authorization", required = true } },
          { user_id_header = typedefs.header_name { default = "X-User-Id", required = true } }
        }, 
      }, 
    },
  },
}
