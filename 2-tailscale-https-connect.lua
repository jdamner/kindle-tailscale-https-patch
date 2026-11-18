-- KOReader user patch: HTTPS through the KOReader Tailscale HTTP proxy.
--
-- Install as:
--   /mnt/us/koreader/patches/2-tailscale-https-connect.lua
--
-- This avoids modifying common/ssl/https.lua directly. It is intended for
-- KOReader's userspace Tailscale mode, where the daemon exposes an HTTP
-- CONNECT proxy on 127.0.0.1:1056.

local userpatch = require("userpatch")

local function patch_https_transport()
    local socket = require("socket")
    local ssl = require("ssl")
    local ltn12 = require("ltn12")
    local http = require("socket.http")
    local url = require("socket.url")
    local https = require("ssl.https")
    local try = socket.try

    if https._tailscale_connect_patch then
        return
    end

    local cfg = {
        protocol = "any",
        options = {"all", "no_sslv2", "no_sslv3", "no_tlsv1"},
        verify = "none",
    }

    local function default_https_port(value)
        return url.build(url.parse(value, {port = https.PORT}))
    end

    local function url_to_request(value, body, result)
        local request = {
            url = default_https_port(value),
            method = body and "POST" or "GET",
            sink = ltn12.sink.table(result),
        }
        if body then
            request.source = ltn12.source.string(body)
            request.headers = {
                ["content-length"] = #body,
                ["content-type"] = "application/x-www-form-urlencoded",
            }
        end
        return request
    end

    local function register_socket(conn)
        local methods = getmetatable(conn.sock).__index
        for name, method in pairs(methods) do
            if type(method) == "function" then
                conn[name] = function(self, ...)
                    return method(self.sock, ...)
                end
            end
        end
    end

    local function connect_through_proxy(sock, proxy, target_host, target_port)
        local proxy_url = url.parse(proxy)
        local proxy_host = proxy_url.host
        local proxy_port = tonumber(proxy_url.port) or 3128
        try(sock:connect(proxy_host, proxy_port))

        local authority = target_host .. ":" .. tostring(target_port)
        local request = "CONNECT " .. authority .. " HTTP/1.1\r\n"
            .. "Host: " .. authority .. "\r\n"
        if proxy_url.user and proxy_url.password then
            local mime = require("mime")
            request = request .. "Proxy-Authorization: Basic "
                .. mime.b64(url.unescape(proxy_url.user) .. ":"
                    .. url.unescape(proxy_url.password)) .. "\r\n"
        end
        try(sock:send(request .. "\r\n"))

        local line = try(sock:receive("*l"))
        local code = tonumber(line:match("^HTTP/%d%.%d%s+(%d+)"))
        if code ~= 200 then
            try(nil, "proxy CONNECT failed: " .. line)
        end
        repeat
            line = try(sock:receive("*l"))
        until line == ""
    end

    local function tls_socket(params)
        params = params or {}
        for key, value in pairs(cfg) do
            params[key] = params[key] or value
        end
        params.mode = "client"

        return function()
            local conn = {sock = try(socket.tcp())}
            local set_timeout = getmetatable(conn.sock).__index.settimeout

            function conn:settimeout()
                return set_timeout(self.sock, https.TIMEOUT)
            end

            function conn:connect(host, port)
                local target = url.parse(params.url)
                local target_host = target.host or host
                local target_port = tonumber(target.port) or https.PORT
                local proxy = params.forced_proxy

                if proxy then
                    connect_through_proxy(self.sock, proxy, target_host, target_port)
                else
                    try(self.sock:connect(host, port))
                end

                self.sock = try(ssl.wrap(self.sock, params))
                self.sock:sni(target_host)
                self.sock:settimeout(https.TIMEOUT)
                try(self.sock:dohandshake())
                register_socket(self)
                return 1
            end

            return conn
        end
    end

    https.tcp = tls_socket
    https.request = function(request_arg, body)
        local result = {}
        local string_request = type(request_arg) == "string"
        local request = request_arg

        if string_request then
            request = url_to_request(request_arg, body, result)
        else
            request.url = default_https_port(request.url)
        end

        if request.redirect then
            return nil, "redirect not supported"
        elseif request.create then
            return nil, "create function not permitted"
        end

        local global_proxy = http.PROXY
        request.forced_proxy = request.proxy or global_proxy
        request.proxy = nil
        http.PROXY = nil
        request.create = tls_socket(request)
        local ok, response, code, headers, status = pcall(http.request, request)
        http.PROXY = global_proxy
        if not ok then
            return nil, response
        end
        if response and string_request then
            return table.concat(result), code, headers, status
        end
        return response, code, headers, status
    end
    https._tailscale_connect_patch = true
end

local function enable_tailscale_proxy(plugin)
    if not plugin or not plugin.settings then
        return
    end
    plugin.settings:saveSetting("auto_http_proxy", true)
    if plugin.flushSettings then
        plugin:flushSettings()
    end
    if plugin.enableHTTPProxyIfNeeded then
        plugin:enableHTTPProxyIfNeeded()
    end
end

local function patch_cwngsync()
    patch_https_transport()
end

userpatch.registerPatchPluginFunc("cwngsync", patch_cwngsync)
userpatch.registerPatchPluginFunc("tailscale", enable_tailscale_proxy)
