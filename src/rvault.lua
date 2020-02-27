--
-- Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
-- All rights reserved.
--
-- Use is subject to license terms, as specified in the LICENSE file.
--

local cjson = require "cjson.safe"
local otp = require "otp"
local uuid = require "uuid"
local lfs = require "lfs"

uuid.randomseed(os.time() .. os.clock())

--
-- Constants.
--

OTP_ISSUER = "rvault"
DATA_DIR = "/data"
CRYPTO_MAX_EKEY_LENGTH = 96 + 32 + 1
UUID_TRIM_STR_LENGTH = 32

--
-- A few system and I/O related helpers.
--

local function unix_time()
  return os.time(os.date("!*t"))
end

local function get_body()
  ngx.req.read_body() -- fetch the body data
  local data = ngx.req.get_body_data()
  if not data then
    ngx.status = ngx.HTTP_BAD_REQUEST
    ngx.say("Invalid JSON: no data")
    ngx.exit(ngx.HTTP_BAD_REQUEST)
  end
  return data
end

local function write_file(uid, name, data)
  local f, errmsg = io.open(DATA_DIR .. "/" .. uid .. "/" .. name, "w")
  if not f then
    ngx.log(ngx.ERR, "io:open() failed" .. errmsg);
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  f:write(data)
  f:flush(data)
  f:close()
end

local function read_file(uid, name)
  local f, errmsg = io.open(DATA_DIR .. "/" .. uid .. "/" .. name, "r")
  if not f then
    ngx.log(ngx.ERR, "io:open() failed" .. errmsg);
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  local c = f:read("*all")
  f:close()
  return c
end

local function check_user_path(uid, name)
  local fname = name and ("/" .. name) or ""
  local f = io.open(DATA_DIR .. "/" .. uid .. fname)
  if not f then
    return false
  end
  f:close()
  return true
end

local function get_qr_code(url)
  local f = io.popen("qrencode -t ASCIIi '" .. url .. "'", "r")
  local qrcode = f:read("*a")
  f:close()
  return qrcode
end

--
-- rvault_api_register: register the user given its UID and key.
--
-- API route: POST /api/v1/register
-- Input: UID and key.
-- Output: TOTP key.
--
function rvault_api_register()
  ngx.header.content_type = 'text/plain';
  if ngx.var.request_method ~= 'POST' then
    ngx.exit(ngx.HTTP_NOT_ALLOWED)
  end

  --
  -- Read the payload; fetch the UID and the key; validate them.
  --
  local payload, errmsg = cjson.decode(get_body())
  if not payload then
    ngx.status = ngx.HTTP_BAD_REQUEST
    return ngx.say("Invalid JSON: " .. errmsg)
  end

  if not payload.uid or not payload.key then
    ngx.status = ngx.HTTP_BAD_REQUEST
    return ngx.say("'uid' and 'key' must be present in the JSON object")
  end

  local uid = payload.uid:gsub("-", "")
  local key = payload.key

  if #uid ~= UUID_TRIM_STR_LENGTH or uid:match("%W") then
    ngx.status = ngx.HTTP_BAD_REQUEST
    return ngx.say("'uid' must be a valid UUID string")
  end
  if #key == 0 or #key > CRYPTO_MAX_EKEY_LENGTH or key:match("[^%w:]") then
    ngx.status = ngx.HTTP_BAD_REQUEST
    return ngx.say("'key' must be a valid hex string")
  end

  --
  -- Check that the UID has been created and no TOTP stored.
  --
  if not check_user_path(uid) then
    ngx.status = ngx.HTTP_NOT_FOUND
    ngx.log(ngx.WARN, "UID " .. uid .. " is not setup");
    return ngx.say("UID " .. uid .. " is not setup");
  end
  if check_user_path(uid, "totp") then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.log(ngx.WARN, "UID " .. uid .. " is already registered");
    return ngx.say("UID " .. uid .. " is already registered");
  end

  local email = read_file(uid, "email")
  assert(email)

  --
  -- Write the key and create TOTP.
  --
  write_file(uid, "key", key)

  local totp = otp.new_totp(16)
  write_file(uid, "totp", totp:serialize())

  --
  -- Respond with the ASCII QR code.
  --
  local totp_url = totp:get_url(OTP_ISSUER, email .. " " .. uid)
  ngx.say(get_qr_code(totp_url))
  ngx.say("Alternatively, use the plaintext key: " .. totp:get_key())
  return ngx.exit(ngx.HTTP_CREATED)
end

--
-- rvault_api_auth: authenticate using TOTP.
--
-- API route: POST /api/v1/auth
-- Input: UID and TOTP code.
-- Output: key.
--
function rvault_api_auth()
  ngx.header.content_type = 'text/plain';
  if ngx.var.request_method ~= 'POST' then
    ngx.exit(ngx.HTTP_NOT_ALLOWED)
  end

  payload, errmsg = cjson.decode(get_body())
  if not payload then
    ngx.status = ngx.HTTP_BAD_REQUEST
    return ngx.say("Invalid JSON: " .. errmsg)
  end

  if not payload.uid or not payload.code then
    ngx.status = ngx.HTTP_BAD_REQUEST
    return ngx.say("'uid' and 'code' must be present in the JSON object")
  end

  local uid = payload.uid:gsub("-", "")
  local code = payload.code

  if #uid ~= UUID_TRIM_STR_LENGTH or uid:match("%W") then
    ngx.status = ngx.HTTP_BAD_REQUEST
    return ngx.say("'uid' must be a valid UUID string")
  end

  -- Rate-limit the requests.
  -- if (unix_time() - last_time()) > 1 then
  --   ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
  -- end

  local totp_s = read_file(uid, "totp")
  assert(totp_s)
  local totp = otp.read(totp_s)

  --
  -- Verify TOTP code.
  --
  if totp:verify(code) then
    local key = read_file(uid, "key")
    ngx.say(key) -- return the key
    ngx.exit(ngx.HTTP_OK)
  end

  ngx.sleep(1) -- delay the response; XXX rate-limit properly
  ngx.exit(ngx.HTTP_FORBIDDEN)
end

function rvault_api_setup()
  ngx.header.content_type = 'text/plain';
  if ngx.var.request_method ~= 'POST' then
    ngx.exit(ngx.HTTP_NOT_ALLOWED)
  end
  local uid = uuid():gsub("-", "")
  if not lfs.mkdir(DATA_DIR .. "/" .. uid) then
    -- Just hope that the user will re-try.
    ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
  end

  local payload, errmsg = cjson.decode(get_body())
  if not payload then
    ngx.status = ngx.HTTP_BAD_REQUEST
    return ngx.say("Invalid JSON: " .. errmsg)
  end
  if not payload.email then
    ngx.status = ngx.HTTP_BAD_REQUEST
    return ngx.say("'email' must be present in the JSON object")
  end
  write_file(uid, "email", payload.email)

  ngx.say(uid)
  ngx.exit(ngx.HTTP_OK)
end
