export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/offerwall/postback") {
      if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: { Allow: "POST" } });
      const target = new URL("https://revnora-backend.charvisharma7619.workers.dev/api/offerwall/postback");
      target.search = url.search;
      const headers = new Headers(request.headers);
      headers.delete("host");
      const upstream = new Request(target.toString(), {
        method: "POST",
        headers,
        body: request.body,
        redirect: "manual"
      });
      const response = await fetch(upstream);
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
      });
    }
    return env.ASSETS.fetch(request);
  }
};
