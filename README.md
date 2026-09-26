# Pool Member Diagnostic Page

A single PHP page for lab load balancer pools. Deploy the same files on every pool member, browse to the virtual server, and the page shows which member answered, how the request reached it, and whether persistence is working.

## What it shows

- Server IP, port and hostname of the member that handled the request
- Client IP (from `X-Forwarded-For` when present) and the proxy address it came through
- Protocol, method, URI and user agent
- Numbered image tiles, each fetched as a separate request, so you can see requests spread across members when there's no persistence
- Any recognized persistence cookie (F5 BIG-IP, NetScaler, AWS, Azure, GCP, Cloudflare, HAProxy, Apache). F5 BIG-IP cookies are decoded to the member IP and port and compared with the local server.
- All request headers received, in a collapsible table

The status panel is green when the member received the request over TLS and red when it didn't. This reflects the load-balancer-to-server leg, not the client-to-VIP leg.

## Requirements

- PHP 7.4 or later
- Apache, nginx with PHP-FPM, or IIS

## Setup

Copy the files to the web root on each pool member:

```
index.php
images/1.png
images/2.png
images/3.png
```

Give each member its own set of images (for example, member 1 serves images labeled "1", member 2 serves "2") so the tiles show which member served each request. Any `images/<n>.png` files present are displayed in numeric order.

For an HTTPS pool, enable TLS on the member's web server. Nothing in `index.php` changes between HTTP and HTTPS pools or between members.

## Reading the results

| Tiles | Persistence cookie | Meaning |
| --- | --- | --- |
| Mixed numbers | None | Load balancing without persistence |
| All the same | Present, "This server" | Cookie persistence working |
| All the same | None | Source address persistence, or a single active member |
| Mixed numbers | Present, "Different member" | Persistence not being honored |

Caching is disabled on the page and the image URLs carry a cache-busting parameter, so each reload makes fresh requests.

## Notes

This is a lab tool. It displays internal addresses and every request header, and it trusts `X-Forwarded-For` as sent. Don't expose it to untrusted networks.
