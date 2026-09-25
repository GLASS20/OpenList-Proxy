// src/const.js
// Environment variables will be injected by Cloudflare Worker runtime
// These will be set during the fetch function execution

let ADDRESS, TOKEN, WORKER_ADDRESS, DISABLE_SIGN, X_OPENLIST_TOKEN;

// Function to initialize constants from environment variables
function initConstants(env) {
  // OpenList 后端服务器地址 (不要包含尾随斜杠)
  // OpenList backend server address (do not include trailing slash)
  ADDRESS = env.ADDRESS || "YOUR_ADDRESS";

  // OpenList 服务器的 API 访问令牌 (密钥)
  // API access token (secret key) for OpenList server
  TOKEN = env.TOKEN || "YOUR_TOKEN";

  // Cloudflare Worker 的完整地址
  // Full address of your Cloudflare Worker
  WORKER_ADDRESS = env.WORKER_ADDRESS || "YOUR_WORKER_ADDRESS";

  // 自定义 X_OPENLIST_TOKEN 绕过 Challenge
  X_OPENLIST_TOKEN = env.X_OPENLIST_TOKEN || "YOUR_X_OPENLIST_TOKEN";

  // 是否禁用签名验证
  // Whether to disable signature verification
  DISABLE_SIGN =
    env.DISABLE_SIGN === "true" ||
    env.DISABLE_SIGN === true ||
    false;
}


// ------------------------------------------------------------
// 允许从客户端继承的最小 Header
//
// 这些 Header 用于文件下载/断点续传，不包含客户端身份特征。
// ------------------------------------------------------------

const ALLOWED_CLIENT_HEADERS = new Set([
  "range",
  "if-range",
  "if-none-match",
  "if-modified-since",
]);


// ------------------------------------------------------------
// OpenList 返回的、允许发送给最终文件服务器的 Header
//
// 这些 Header 来自 OpenList，而不是直接继承客户端。
// ------------------------------------------------------------

const ALLOWED_OPENLIST_HEADERS = new Set([
  // 下载认证/授权
  "authorization",
  "cookie",

  // 某些文件服务器需要 Referer / User-Agent
  // 如果 OpenList 没有返回，它们不会被主动添加。
  "referer",
  "user-agent",

  // 文件下载控制
  "range",
  "if-range",
  "if-none-match",
  "if-modified-since",
]);


// ------------------------------------------------------------
// OpenList Header 额外禁止项
//
// 即使未来 ALLOWED_OPENLIST_HEADERS 扩展，也禁止这些代理/CDN特征。
// ------------------------------------------------------------

const BLOCKED_UPSTREAM_HEADERS = new Set([
  // IP / Proxy
  "x-forwarded-for",
  "x-real-ip",
  "forwarded",
  "forwarded-for",
  "true-client-ip",
  "x-client-ip",

  // Fastly
  "fastly-client",
  "fastly-client-ip",
  "fastly-ff",
  "fastly-ssl",
  "fastly-orig-accept-encoding",
  "fastly-original-cookie",
  "fastly-original-url",
  "fastly-vary-string",
  "fastly-temp-xff",
  "fastly-debug-path",
  "fastly-debug-ttl",
  "fastly-debug-digest",

  // Forwarding
  "x-forwarded-host",
  "x-forwarded-server",
  "x-forwarded-proto",
  "x-forwarded-port",

  // Cloudflare
  "cf-connecting-ip",
  "cf-connecting-ipv6",
  "cf-ray",
  "cf-ipcountry",
  "cf-visitor",
  "cf-worker",
  "cf-ew-via",
  "cf-pseudo-ipv4",

  // CDN / Proxy
  "cdn-loop",
  "via",

  // Varnish / Fastly internal
  "x-varnish",
  "x-timer",

  // Browser fingerprint
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site",
  "sec-fetch-user",
  "upgrade-insecure-requests",

  // Browser environment information
  "accept-language",
  "origin",

  // Connection / proxy
  "connection",
  "keep-alive",
  "proxy-connection",

  // Cache fingerprint
  "cache-control",

  // 不允许 Host 由 Header 注入
  "host",
]);


// ------------------------------------------------------------
// Privacy Warning:
//
// 禁用签名会导致任何知道路径的人都可能访问文件。
// ------------------------------------------------------------


// src/verify.js

/**
 * Verifies a signed string with expiration check.
 *
 * @param {string} data - Original data.
 * @param {string} _sign - Signed string.
 * @returns {Promise<string>} Error message if invalid, empty string if valid.
 */
var verify = async (data, _sign) => {
  if (DISABLE_SIGN) {
    return "";
  }

  const signSlice = _sign.split(":");

  if (!signSlice[signSlice.length - 1]) {
    return "expire missing";
  }

  const expire = parseInt(signSlice[signSlice.length - 1]);

  if (isNaN(expire)) {
    return "expire invalid";
  }

  if (expire < Date.now() / 1e3 && expire > 0) {
    return "expire expired";
  }

  const right = await hmacSha256Sign(data, expire);

  if (_sign !== right) {
    return "sign mismatch";
  }

  return "";
};


/**
 * Generates an HMAC-SHA256 signature with expiration.
 *
 * @param {string} data - The data to sign.
 * @param {number} expire - Expiry timestamp in seconds.
 * @returns {Promise<string>} The signed string.
 */
var hmacSha256Sign = async (data, expire) => {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(TOKEN),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign", "verify"]
  );

  const buf = await crypto.subtle.sign(
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    key,
    new TextEncoder().encode(`${data}:${expire}`)
  );

  return (
    btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_") +
    ":" +
    expire
  );
};


// ------------------------------------------------------------
// 创建“干净”的上游 Header
// ------------------------------------------------------------

function buildUpstreamHeaders(clientRequest, openListHeader) {
  const headers = new Headers();

  // ----------------------------------------------------------
  // 1. 只从客户端继承下载控制 Header
  // ----------------------------------------------------------

  for (const name of ALLOWED_CLIENT_HEADERS) {
    const value = clientRequest.headers.get(name);

    if (value !== null) {
      headers.set(name, value);
    }
  }


  // ----------------------------------------------------------
  // 2. OpenList 返回的 Header
  //
  // 只接受明确允许的 Header。
  // Fastly / Cloudflare / Proxy / Browser 特征全部拒绝。
  // ----------------------------------------------------------

  if (openListHeader && typeof openListHeader === "object") {
    for (const [key, values] of Object.entries(openListHeader)) {
      const lowerKey = key.toLowerCase();

      // 绝对禁止
      if (BLOCKED_UPSTREAM_HEADERS.has(lowerKey)) {
        continue;
      }

      // 不在 OpenList 白名单中
      if (!ALLOWED_OPENLIST_HEADERS.has(lowerKey)) {
        continue;
      }

      if (Array.isArray(values)) {
        // 对同一个 Header，使用 set 而不是 append，
        // 避免构造多余 Header 值。
        if (values.length > 0) {
          headers.set(lowerKey, String(values[0]));
        }
      } else if (values !== undefined && values !== null) {
        headers.set(lowerKey, String(values));
      }
    }
  }

  return headers;
}


// ------------------------------------------------------------
// src/handleDownload.js
// ------------------------------------------------------------

/**
 * Handles download requests with signature verification and CORS.
 *
 * @param {Request} request - Incoming request.
 * @returns {Promise<Response>}
 */
async function handleDownload(request) {
  const origin = request.headers.get("origin") ?? "*";

  const url = new URL(request.url);
  const path = decodeURIComponent(url.pathname);


  // ----------------------------------------------------------
  // Signature verification
  // ----------------------------------------------------------

  if (!DISABLE_SIGN) {
    const sign = url.searchParams.get("sign") ?? "";

    const verifyResult = await verify(path, sign);

    if (verifyResult !== "") {
      return new Response(
        JSON.stringify({
          code: 401,
          message: verifyResult,
        }),
        {
          status: 401,
          headers: {
            "content-type": "application/json;charset=UTF-8",
            "Access-Control-Allow-Origin": origin,
          },
        }
      );
    }
  }


  // ----------------------------------------------------------
  // 请求 OpenList 获取真实文件 URL
  // ----------------------------------------------------------

  const resp = await fetch(`${ADDRESS}/api/fs/link`, {
    method: "POST",

    headers: {
      "content-type": "application/json;charset=UTF-8",
      Authorization: TOKEN,
      "X-OpenList-Token": X_OPENLIST_TOKEN,
    },

    body: JSON.stringify({
      path,
    }),
  });

  const res = await resp.json();

  if (res.code !== 200) {
    return new Response(JSON.stringify(res), {
      headers: {
        "content-type": "application/json;charset=UTF-8",
        "Access-Control-Allow-Origin": origin,
      },
    });
  }


  // ----------------------------------------------------------
  // 创建完全独立的上游请求
  //
  // 关键：
  //
  // ❌ 不再：
  //    new Request(res.data.url, request)
  //
  // ✅ 而是：
  //    重新构造 Header
  //
  // 因此 Fastly → Worker 的 Header 不会被整体继承。
  // ----------------------------------------------------------

  const upstreamHeaders = buildUpstreamHeaders(
    request,
    res.data.header
  );


  // ----------------------------------------------------------
  // 创建真正发送给文件服务器的 Request
  // ----------------------------------------------------------

  let upstreamRequest = new Request(
    res.data.url,
    {
      method:
        request.method === "HEAD"
          ? "HEAD"
          : "GET",

      headers: upstreamHeaders,

      redirect: "manual",
    }
  );


  // ----------------------------------------------------------
  // 请求文件服务器
  // ----------------------------------------------------------

  let response = await fetch(upstreamRequest);


  // ----------------------------------------------------------
  // 处理重定向
  // ----------------------------------------------------------

  while (
    response.status >= 300 &&
    response.status < 400
  ) {
    const location = response.headers.get("Location");

    if (!location) {
      break;
    }


    // --------------------------------------------------------
    // 重定向回当前 Worker
    // --------------------------------------------------------

    if (location.startsWith(`${WORKER_ADDRESS}/`)) {
      const redirectRequest = new Request(
        location,
        {
          method:
            request.method === "HEAD"
              ? "HEAD"
              : "GET",

          // 继续使用已经过滤过的干净 Header
          headers: new Headers(upstreamHeaders),

          redirect: "manual",
        }
      );

      return await handleRequest(redirectRequest);
    }


    // --------------------------------------------------------
    // 外部重定向
    //
    // 不继承上一跳 request，
    // 继续使用同一套干净 Header。
    // --------------------------------------------------------

    upstreamRequest = new Request(
      location,
      {
        method:
          request.method === "HEAD"
            ? "HEAD"
            : "GET",

        headers: new Headers(upstreamHeaders),

        redirect: "manual",
      }
    );

    response = await fetch(upstreamRequest);
  }


  // ----------------------------------------------------------
  // 清理响应 Header
  // ----------------------------------------------------------

  response = new Response(
    response.body,
    response
  );

  response.headers.delete("set-cookie");
  response.headers.delete("Alt-Svc");

  response.headers.set(
    "Access-Control-Allow-Origin",
    origin
  );

  response.headers.append(
    "Vary",
    "Origin"
  );

  return response;
}


// ------------------------------------------------------------
// src/handleOptions.js
// ------------------------------------------------------------

/**
 * Handles preflight CORS (OPTIONS) requests.
 *
 * @param {Request} request
 * @returns {Response}
 */
function handleOptions(request) {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Max-Age": "86400",
  };

  const headers = request.headers;

  if (
    headers.get("Origin") !== null &&
    headers.get("Access-Control-Request-Method") !== null
  ) {
    const respHeaders = {
      ...corsHeaders,

      "Access-Control-Allow-Headers":
        headers.get(
          "Access-Control-Request-Headers"
        ) || "",
    };

    return new Response(null, {
      headers: respHeaders,
    });
  }

  return new Response(null, {
    headers: {
      Allow: "GET, HEAD, OPTIONS",
    },
  });
}


// ------------------------------------------------------------
// src/handleRequest.js
// ------------------------------------------------------------

/**
 * Main request handler.
 *
 * @param {Request} request
 * @returns {Promise<Response>}
 */
async function handleRequest(request) {
  if (request.method === "OPTIONS") {
    return handleOptions(request);
  }

  return await handleDownload(request);
}


// ------------------------------------------------------------
// src/index.js
// ------------------------------------------------------------

/**
 * Cloudflare Worker entry point.
 *
 * @param {Request} request
 * @param {any} env
 * @param {ExecutionContext} ctx
 * @returns {Promise<Response>}
 */
var src_default = {
  async fetch(request, env, ctx) {
    initConstants(env);

    return await handleRequest(request);
  },
};

export {
  src_default as default
};
