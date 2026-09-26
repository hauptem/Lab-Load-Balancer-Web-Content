# Lab Load Balancer Web Content

A single PHP page for load balancer pool members in a lab environment. 

## What it shows

- Server IP, port and hostname of the member that handled the request
- Client IP (from `X-Forwarded-For` when present) and the proxy address it came through
- Protocol, method, URI and user agent
- Numbered image tiles, each fetched as a separate request, so you can see requests spread across members when there's no persistence
- Any recognized persistence cookie (F5 BIG-IP, NetScaler, AWS, Azure, GCP, Cloudflare, HAProxy, Apache). F5 BIG-IP cookies are decoded to the member IP and port and compared with the local server.
- All request headers received

## Requirements

- PHP 7.4 or later
- Apache, nginx with PHP-FPM, or IIS

## Setup

Copy the files to the web root on each pool member and ensure that each member has three image files numbered to their pool member number. For example, Pool member 1 will have the "1" png three times all named:

```
index.php
images/1.png
images/2.png
images/3.png
```

Give each member its own set of images (for example, member 1 serves three images labeled "1", member 2 serves three "2" images and so on)

## Notes

This is meant for a lab to replicate testing persistence, load balance algorithms, etc.
