const ALLOWED_PATHS = [
  /^\/api\/updates(?:\/[\w-]+)?$/,
  /^\/api\/members(?:\/[\w-]+)?$/,
  /^\/api\/gallery(?:\/[\w-]+)?$/,
  /^\/api\/chat(?:\/[\w-]+)?$/,
  /^\/api\/stats$/
];

const ALLOWED_METHODS = new Set(["GET", "POST", "PATCH", "DELETE"]);
const MAX_BODY_BYTES = 5 * 1024 * 1024;

function setSecurityHeaders(res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
}

function isAllowedPath(path) {
  return ALLOWED_PATHS.some((pattern) => pattern.test(path));
}

module.exports = async (req, res) => {
  setSecurityHeaders(res);

  if (!ALLOWED_METHODS.has(req.method)) {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  const upstreamBase = process.env.MAGOYE_API_URL;
  const apiKey = process.env.MAGOYE_API_KEY;
  if (!upstreamBase || !apiKey) {
    res.status(500).json({ error: "Server configuration missing" });
    return;
  }

  const path = typeof req.query.path === "string" ? req.query.path : "";
  if (!path.startsWith("/") || !isAllowedPath(path)) {
    res.status(400).json({ error: "Path not allowed" });
    return;
  }

  const contentLength = Number(req.headers["content-length"] || 0);
  if (contentLength > MAX_BODY_BYTES) {
    res.status(413).json({ error: "Payload too large" });
    return;
  }

  const upstreamUrl = new URL(path, upstreamBase).toString();
  const headers = {
    "X-API-Key": apiKey,
    Accept: "application/json"
  };

  const options = { method: req.method, headers };

  if (req.method !== "GET" && req.method !== "DELETE") {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(req.body || {});
  }

  try {
    const upstream = await fetch(upstreamUrl, options);
    const text = await upstream.text();
    res.status(upstream.status);
    const contentType = upstream.headers.get("content-type") || "application/json; charset=utf-8";
    res.setHeader("Content-Type", contentType);
    res.send(text);
  } catch (error) {
    res.status(502).json({ error: "Upstream request failed" });
  }
};
