import { NextResponse, type NextRequest } from "next/server";

// The API takes the client address from X-Forwarded-For when the request comes from this server.
// Next.js forwards that header as the browser sent it and does not append the real address, so a
// client talking to this server directly could claim any address. Strip it unless a reverse proxy
// in front (load balancer, ingress, nginx) appends the real client address: set CTEM_UPSTREAM_PROXY=true.
export function proxy(request: NextRequest) {
  if (process.env.CTEM_UPSTREAM_PROXY === "true") return NextResponse.next();
  const headers = new Headers(request.headers);
  headers.delete("x-forwarded-for");
  headers.delete("x-real-ip");
  return NextResponse.next({ request: { headers } });
}

export const config = { matcher: "/api/:path*" };
