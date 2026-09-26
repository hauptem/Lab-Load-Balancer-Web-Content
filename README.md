# Lab Load Balancer Web Content

Ever take an F5 LTM class and see web content for pools that show you what the Big-IP is doing and what it knows? This is a single PHP page and some png files useful for load balancer pool member webservers in a lab environment. 

<img width="1180" height="772" alt="Image" src="https://github.com/user-attachments/assets/9de51d16-2b8a-42ba-93cb-070703bbcf8f" />
<img width="1174" height="867" alt="Image" src="https://github.com/user-attachments/assets/75b55014-ca4a-4a91-8ccb-f14c49a10eba" />

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

Copy the files to the web root on each pool member and ensure that each member has three image files numbered to their pool member number. For example, pool member 1 will have the "1" png three times all named like this:

```
index.php
images/1.png
images/2.png
images/3.png
```

Pool 2 will have the 2 png named: 1.png, 2.png, 3.png and so on.

## Notes

This is meant for a lab to replicate testing persistence, load balance algorithms, etc.

**Technical Disclaimer:**

- This software is provided "AS IS" without warranty of any kind.
- The authors and contributors are not responsible for any damages or issues that may arise from its use.
- Always test thoroughly in non-production environments before deployment.
- Review and understand all code before deploying.

By using this software, you acknowledge that you have read and understood these disclaimers and agree to use this solution at your own risk.
