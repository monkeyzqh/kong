local utils = require "kong.tools.utils"

local function find_http_credentials(authorization_header)
  if not authorization_header then
    return
  end

  local iterator, iter_err = ngx.re.gmatch(authorization_header,
    "\\s*[Bb]asic\\s*(.+)")
  if not iterator then
    ngx.log(ngx.ERR, iter_err)
    return
  end

  local m, err = iterator()

  if err then
    ngx.log(ngx.ERR, err)
    return
  end

  if m and m[1] then
    local decoded_basic = ngx.decode_base64(m[1])

    if decoded_basic then
      local user_pass = utils.split(decoded_basic, ":")
      return user_pass[1], user_pass[2]
    end
  end
end

return {
  filter_access_by_method = function(method)
    if ngx.req.get_method() ~= method then
      ngx.status = ngx.HTTP_NOT_ALLOWED
      ngx.header['x-powered-by'] = "mock_upstream"
      ngx.header['X-POWERED-BY'] = "mock_upstream"
      ngx.say("The method is not allowed for the requested URL")
      return ngx.exit(ngx.HTTP_NOT_ALLOWED)
    end
  end,

  filter_access_by_basic_auth = function(expected_username, expected_password)
    local headers = ngx.req.get_headers()

    local username, password =
      find_http_credentials(headers["proxy-authorization"])

    if not username then
      username, password =
        find_http_credentials(headers["authorization"])
    end

    if username ~= expected_username or password ~= expected_password then
      ngx.header["WWW-Authenticate"] = "mock_upstream"
      ngx.header['x-powered-by'] = "mock_upstream"
      ngx.header['X-POWERED-BY'] = "mock_upstream"
      return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
  end,

  send_json_response = function(tbl)
    local cjson = require "cjson"
    ngx.header['x-powered-by'] = "mock_upstream"
    ngx.header['X-POWERED-BY'] = "mock_upstream"
    ngx.say(cjson.encode(tbl))
  end,

  get_request_url = function()
    return string.format("%s://%s%s", ngx.var.scheme,
      ngx.var.host,
      ngx.var.request_uri)
  end,

  parse_post_data = function(headers)
    local cjson_safe         = require "cjson.safe"
    local cjson              = require "cjson"
    local data, form, params = "", {}, cjson.null
    local ct                 = headers["content-type"]
    if ct then
      ngx.req.read_body()
      if string.find(ct, "application/x-www-form-urlencoded", nil, true) then
        form = ngx.req.get_post_args()
      elseif string.find(ct, "application/json", nil, true) then
        local err
        data, err = ngx.req.get_body_data()
        if not data then
          ngx.log(ngx.ERR, "could not read body data: ", err)
          return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end
        -- ignore decoding errors
        params = cjson_safe.decode(data) or cjson.null
      end
    end

    return data, form, params
  end,

  serve_web_sockets = function()
    local server = require "resty.websocket.server"
    local wb, err = server:new{
      timeout = 5000,
      max_payload_len = 65535,
    }

    if not wb then
      ngx.log(ngx.ERR, "failed to open websocket: ", err)
      return ngx.exit(444)
    end

    while true do
      local data, typ, err = wb:recv_frame()
      if wb.fatal then
        ngx.log(ngx.ERR, "failed to receive frame: ", err)
        return ngx.exit(444)
      end

      if data then
        if typ == "close" then
          break
        end

        if typ == "ping" then
          local bytes, err = wb:send_pong(data)
          if not bytes then
            ngx.log(ngx.ERR, "failed to send pong: ", err)
            return ngx.exit(444)
          end

        elseif typ == "pong" then
          ngx.log(ngx.INFO, "client ponged")

        elseif typ == "text" then
          local bytes, err = wb:send_text(data)
          if not bytes then
            ngx.log(ngx.ERR, "failed to send text: ", err)
            return ngx.exit(444)
          end
        end

      else
        local bytes, err = wb:send_ping()
        if not bytes then
          ngx.log(ngx.ERR, "failed to send ping: ", err)
          return ngx.exit(444)
        end
      end
    end

    wb:send_close()
  end,
}
