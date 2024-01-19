Leverage Kong with a custom plugin to centralize the integration and allow each microservice to focus on the business logic.

config:
- authentication_endpoint
- authorization_endpoint

authorization server:
- request data:
  + body: {"uri": "request path"}
  + header: Authorization: Bearer {access_token}

- responsive http code:
  + 200: for ok
  + 401: not not authorize


Refference: https://konghq.com/blog/engineering/custom-authentication-and-authorization-framework-with-kong
