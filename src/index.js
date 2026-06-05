/**
 * Cloudflare Worker Docker Proxy (Modern ES Module Version)
 * 融合了 library 补全、307 强制代理防直连墙、动态路由等特性
 */

const dockerHub = "https://registry-1.docker.io";

export default {
  async fetch(request, env, ctx) {
    ctx.passThroughOnException();

    // 从环境变量获取自定义域名，如果没配置，退化使用请求头中的 host
    const CUSTOM_DOMAIN = env.CUSTOM_DOMAIN || new URL(request.url).hostname;
    
    const routes = {
      [`docker.${CUSTOM_DOMAIN}`]: dockerHub,
      [`quay.${CUSTOM_DOMAIN}`]: "https://quay.io",
      [`gcr.${CUSTOM_DOMAIN}`]: "https://gcr.io",
      [`k8s-gcr.${CUSTOM_DOMAIN}`]: "https://k8s.gcr.io",
      [`k8s.${CUSTOM_DOMAIN}`]: "https://registry.k8s.io",
      [`ghcr.${CUSTOM_DOMAIN}`]: "https://ghcr.io",
      [`cloudsmith.${CUSTOM_DOMAIN}`]: "https://docker.cloudsmith.io",
      [`ecr.${CUSTOM_DOMAIN}`]: "https://public.ecr.aws",
    };

    const url = new URL(request.url);
    const upstream = routes[url.hostname];
    
    if (!upstream) {
      return new Response(JSON.stringify({ error: "Unsupported registry routing", routes: Object.keys(routes) }), { status: 404 });
    }

    const isDockerHub = upstream === dockerHub;
    const authorization = request.headers.get("Authorization");

    // 1. 处理根路径重定向
    if (url.pathname === "/") {
      return Response.redirect(`${url.protocol}//${url.host}/v2/`, 301);
    }

    // 2. 处理 /v2/ 基础验证
    if (url.pathname === "/v2/") {
      const newUrl = new URL(upstream + "/v2/");
      const headers = new Headers();
      if (authorization) headers.set("Authorization", authorization);
      
      const resp = await fetch(newUrl.toString(), { method: "GET", headers, redirect: "follow" });
      if (resp.status === 401) {
        return responseUnauthorized(url);
      }
      return resp;
    }

    // 3. 处理鉴权获取 Token (/v2/auth)
    if (url.pathname === "/v2/auth") {
      const newUrl = new URL(upstream + "/v2/");
      const resp = await fetch(newUrl.toString(), { method: "GET", redirect: "follow" });
      if (resp.status !== 401) return resp;

      const authenticateStr = resp.headers.get("WWW-Authenticate");
      if (!authenticateStr) return resp;

      const wwwAuthenticate = parseAuthenticate(authenticateStr);
      let scope = url.searchParams.get("scope");

      // 针对 Docker Hub 的 library 补全机制
      // 解决 docker pull ubuntu (省略 library) 的鉴权失败问题
      if (scope && isDockerHub) {
        let scopeParts = scope.split(":");
        if (scopeParts.length === 3 && !scopeParts[1].includes("/")) {
          scopeParts[1] = "library/" + scopeParts[1];
          scope = scopeParts.join(":");
        }
      }
      return await fetchToken(wwwAuthenticate, scope, authorization);
    }

    // 4. 针对 Docker Hub 请求路径的 library 补全重定向
    if (isDockerHub) {
      const pathParts = url.pathname.split("/");
      if (pathParts.length === 5) {
        pathParts.splice(2, 0, "library");
        const redirectUrl = new URL(url);
        redirectUrl.pathname = pathParts.join("/");
        return Response.redirect(redirectUrl, 301);
      }
    }

    // 5. 转发核心请求到上游
    const newUrl = new URL(upstream + url.pathname + url.search);
    const newReq = new Request(newUrl, {
      method: request.method,
      headers: request.headers,
      // redirect: isDockerHub ? "manual" : "follow", // Docker Hub 手动处理重定向以隐藏 CDN
      redirect: "manual", // 全部手动处理重定向，统一逻辑，避免部分 CDN 直连被墙问题
    });

    const resp = await fetch(newReq);
    if (resp.status === 401) {
      return responseUnauthorized(url);
    }

    // 6. 核心黑科技：手动代下 307 Blob 文件，防止国内直连 CDN 被墙
    // if (isDockerHub && resp.status === 307) {
    if ([301, 302, 307, 308].includes(resp.status)) {
      const location = resp.headers.get("Location");
      if (location) {
        return await fetch(location, { method: "GET", redirect: "follow" });
      }
    }

    return resp;
  }
};

// --- 辅助函数 ---

function parseAuthenticate(authenticateStr) {
  const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
  const matches = authenticateStr.match(re);
  if (!matches || matches.length < 2) {
    throw new Error(`Invalid Www-Authenticate Header: ${authenticateStr}`);
  }
  return { realm: matches[0], service: matches[1] };
}

async function fetchToken(wwwAuthenticate, scope, authorization) {
  const url = new URL(wwwAuthenticate.realm);
  if (wwwAuthenticate.service) url.searchParams.set("service", wwwAuthenticate.service);
  if (scope) url.searchParams.set("scope", scope);
  
  const headers = new Headers();
  if (authorization) headers.set("Authorization", authorization);
  
  return await fetch(url, { method: "GET", headers });
}

function responseUnauthorized(url) {
  const headers = new Headers();
  headers.set(
    "Www-Authenticate",
    `Bearer realm="https://${url.hostname}/v2/auth",service="cloudflare-docker-proxy"`
  );
  return new Response(JSON.stringify({ message: "UNAUTHORIZED" }), {
    status: 401,
    headers,
  });
}
