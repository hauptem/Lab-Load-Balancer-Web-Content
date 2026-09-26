<?php
/**
 * Pool member diagnostic page for HTTP and HTTPS pools.
 *
 * Deployed unchanged on every member of both pools behind a load balancer.
 * Reports the server and client endpoints, any recognized load balancer
 * persistence cookie, and every request header received, so load balancing,
 * persistence and header insertion can be verified from a browser. The status panel turns
 * green when this server received the request over TLS and red otherwise.
 *
 * Member identity comes from the server address and the numbered images
 * under images/; nothing in this file is member-specific.
 */

/**
 * Prepares an untrusted value for HTML output: removes tags, HTML-encodes
 * quotes and special characters (ENT_QUOTES, UTF-8), and strips newlines.
 */
function sanitize(string $value): string
{
        $value = trim($value);
        $value = strip_tags($value);
        $value = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        $value = str_replace("\n", '', $value);
        return trim($value);
}

/**
 * Known load balancer persistence cookies, matched by cookie name. There is no
 * standard name, so each product's default is listed; names that are only a
 * documentation convention are marked as such. 'decoder' names a function that
 * turns the value into [ip, port] when the format is public.
 */
const PERSISTENCE_COOKIES = [
        ['pattern' => '/^BIGipServer/',                         'source' => 'F5 BIG-IP',                        'decoder' => 'decodeBigipCookie'],
        ['pattern' => '/^NSC_/',                                'source' => 'Citrix NetScaler',                 'decoder' => null],
        ['pattern' => '/^AWSALB(TG)?(CORS)?$/',                 'source' => 'AWS Application Load Balancer',    'decoder' => null],
        ['pattern' => '/^AWSELB(CORS)?$/',                      'source' => 'AWS Classic Load Balancer',        'decoder' => null],
        ['pattern' => '/^ApplicationGatewayAffinity(CORS)?$/',  'source' => 'Azure Application Gateway',        'decoder' => null],
        ['pattern' => '/^ASLBSA(CORS)?$/',                      'source' => 'Azure Front Door',                 'decoder' => null],
        ['pattern' => '/^GCLB$/',                               'source' => 'Google Cloud Load Balancing',      'decoder' => null],
        ['pattern' => '/^__cflb$/',                             'source' => 'Cloudflare Load Balancing',        'decoder' => null],
        ['pattern' => '/^SERVERID$/',                           'source' => 'HAProxy (conventional name)',      'decoder' => null],
        ['pattern' => '/^ROUTEID$/',                            'source' => 'Apache mod_proxy_balancer (conventional name)', 'decoder' => null],
];

/**
 * Decodes an F5 BIG-IP persistence cookie value (F5 K6917).
 *
 * Supported formats:
 *   IPv4, default route domain:  <ip>.<port>.0000
 *     ip is the address as a little-endian 32-bit integer;
 *     port is byte-swapped (80 -> 20480, 443 -> 47873).
 *   IPv4, non-default route domain:  rd<id>o00000000000000000000ffff<hex ip>o<port>
 *     IPv4-mapped IPv6 address in hex; port in plain decimal.
 *
 * Encrypted cookies and IPv6 member formats are not decoded.
 *
 * @return array{0: string, 1: int}|null [ip, port], or null when the format is not recognized
 */
function decodeBigipCookie(string $cookieValue): ?array
{
        if (preg_match('/^(\d+)\.(\d+)\.0000$/', $cookieValue, $match)) {
                $encodedIp   = (int) $match[1];
                $encodedPort = (int) $match[2];
                $ip = implode('.', [
                        $encodedIp & 255,
                        ($encodedIp >> 8) & 255,
                        ($encodedIp >> 16) & 255,
                        ($encodedIp >> 24) & 255,
                ]);
                $port = (($encodedPort & 255) << 8) | ($encodedPort >> 8);
                return [$ip, $port];
        }
        if (preg_match('/^rd\d+o0{20}ffff([0-9a-f]{8})o(\d+)$/i', $cookieValue, $match)) {
                return [long2ip(hexdec($match[1])), (int) $match[2]];
        }
        return null;
}

// Disable caching in browsers and intermediaries (RFC 9111 section 5.2.2).
// Pragma and a past Expires cover HTTP/1.0 caches. Must run before any output.
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');

// Server-side TLS state: whether this member received the request over TLS,
// i.e. the load-balancer-to-server leg. HTTPS is set by the web server, not by the
// client: Apache mod_ssl and IIS set it to "on", nginx passes it through
// fastcgi_params ("fastcgi_param HTTPS $https if_not_empty"). IIS sets "off"
// on plain connections. REQUEST_SCHEME covers servers that only set that.
$https   = strtolower((string) ($_SERVER['HTTPS'] ?? ''));
$isTls   = ($https !== '' && $https !== 'off')
        || strtolower((string) ($_SERVER['REQUEST_SCHEME'] ?? '')) === 'https';
$serverLegProtocol = $isTls ? 'HTTPS' : 'HTTP';

// Request and connection data from the SAPI (RFC 3875 meta-variables).
// Every value is sanitized once here and echoed as-is below.
$forwardedFor   = sanitize($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
$remoteAddr     = sanitize($_SERVER['REMOTE_ADDR'] ?? '');
$clientPort     = sanitize($_SERVER['REMOTE_PORT'] ?? '');
$requestMethod  = sanitize($_SERVER['REQUEST_METHOD'] ?? '');
$requestUri     = sanitize($_SERVER['REQUEST_URI'] ?? '');
$httpProtocol   = sanitize($_SERVER['SERVER_PROTOCOL'] ?? '');
$userAgent      = sanitize($_SERVER['HTTP_USER_AGENT'] ?? '');
$serverAddr     = sanitize($_SERVER['SERVER_ADDR'] ?? '');
$serverPort     = sanitize($_SERVER['SERVER_PORT'] ?? '');
$serverHostname = sanitize((string) gethostname());

// Client address: prefer X-Forwarded-For when a proxy inserted it and record
// the immediate peer as the proxy. The header is client-controllable unless
// the proxy overwrites it.
$clientAddr = $forwardedFor !== '' ? $forwardedFor : $remoteAddr;
$proxyAddr  = $forwardedFor !== '' ? $remoteAddr : null;

// Persistence cookies: every cookie received is checked against
// PERSISTENCE_COOKIES. The raw Cookie header is parsed instead of $_COOKIE
// because PHP rewrites '.' and ' ' in cookie names. When a decoder yields a
// member, it is compared with the local address and port (unsanitized).
$persistenceCookies = [];
preg_match_all(
        '/(?:^|;\s*)([^=;\s]+)=([^;]*)/',
        $_SERVER['HTTP_COOKIE'] ?? '',
        $cookieMatches,
        PREG_SET_ORDER
);
foreach ($cookieMatches as [, $cookieName, $cookieValue]) {
        foreach (PERSISTENCE_COOKIES as $known) {
                if (!preg_match($known['pattern'], $cookieName)) {
                        continue;
                }
                $member = $known['decoder'] ? $known['decoder'](trim($cookieValue)) : null;
                $persistenceCookies[] = [
                        'source'       => $known['source'],
                        'name'         => sanitize($cookieName),
                        'value'        => sanitize($cookieValue),
                        'decodable'    => $known['decoder'] !== null,
                        'member'       => $member ? $member[0] . ':' . $member[1] : '',
                        'isThisServer' => $member !== null
                                && $member[0] === ($_SERVER['SERVER_ADDR'] ?? '')
                                && (string) $member[1] === (string) ($_SERVER['SERVER_PORT'] ?? ''),
                ];
                break;
        }
}

// All request headers in received order. getallheaders() exists under Apache,
// FPM (PHP 7.3+) and the CLI server; otherwise names are rebuilt from HTTP_*
// entries in $_SERVER, where order and original case are not preserved.
$requestHeaders = [];
if (function_exists('getallheaders')) {
        foreach (getallheaders() as $headerName => $headerValue) {
                $requestHeaders[sanitize($headerName)] = sanitize($headerValue);
        }
} else {
        foreach ($_SERVER as $key => $headerValue) {
                if (strpos($key, 'HTTP_') === 0) {
                        $headerName = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
                        $requestHeaders[sanitize($headerName)] = sanitize($headerValue);
                }
        }
}

// Member images: every images/<n>.png present, in numeric order. Each is a
// separate request through the load balancer, so adding or removing a file
// changes how many tiles the page shows without touching this code.
$memberImages = [];
foreach (glob(__DIR__ . '/images/*.png') ?: [] as $imagePath) {
        $imageName = basename($imagePath);
        if (preg_match('/^\d+\.png$/', $imageName)) {
                $memberImages[] = $imageName;
        }
}
natsort($memberImages);

// Cache-busting token appended to the image URLs.
$cacheBuster = time();
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= $serverLegProtocol ?> Pool Server</title>
<style>
  /* Theme tokens; --state is green for TLS, red for plain HTTP */
  :root {
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    --bg: #3b424d; --card: #ffffff; --text: #0f172a; --muted: #64748b; --line: #e2e8f0;
    --state: <?= $isTls ? '#16a34a' : '#dc2626' ?>;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; font-family: var(--font); }
  body { background: var(--bg); color: var(--text); padding: 24px 16px; }
  .wrap { max-width: 1150px; margin: 0 auto; display: grid; grid-template-columns: 300px 1fr; background: var(--card); border: 0; border-radius: 14px; overflow: hidden; box-shadow: 0 3px 8px rgba(0,0,0,0.5); }
  /* Status panel: server-side TLS state */
  .side { background: var(--state); color: #fff; padding: 24px 22px; display: flex; flex-direction: column; gap: 18px; }
  .icon { width: 48px; height: 48px; border-radius: 12px; background: rgba(255,255,255,0.18); display: flex; align-items: center; justify-content: center; }
  .icon svg { width: 26px; height: 26px; stroke: #fff; fill: none; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }
  .state { font-size: 22px; font-weight: 700; line-height: 1.2; }
  .state small { white-space: nowrap; display: block; font-size: 13px; font-weight: 400; margin-top: 6px; line-height: 1.5; }
  .srv { margin-top: auto; border-top: 1px solid rgba(255,255,255,0.3); padding-top: 14px; font-size: 16px; font-weight: 600; }
  /* Detail column */
  .content { padding: 24px 28px; min-width: 0; }
  .section { font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 4px; }
  /* Server row: labels share one row and values share the next, baseline-aligned */
  .server { display: grid; grid-template-columns: auto auto minmax(0, 1fr); column-gap: 40px; align-items: baseline; }
  .server .section { margin-bottom: 0; }
  .ip, .pv { font-size: 44px; font-weight: 700; letter-spacing: -1px; margin-top: 4px; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
  .pv { color: var(--muted); }
  .hn { font-size: 28px; font-weight: 700; overflow-wrap: anywhere; }
  /* Shaded group containers and white detail rows */
  .panel { margin-top: 16px; padding: 12px 14px; border-radius: 10px; background: #edf1f6; border: 1px solid #d9e0e8; }
  .cip { font-size: 24px; font-weight: 700; margin-top: 2px; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
  .facts { display: grid; grid-template-columns: repeat(3, 1fr); margin-top: 10px; background: var(--card); border: 1px solid var(--line); border-radius: 10px; }
  .fact { padding: 9px 14px; border-right: 1px solid var(--line); min-width: 0; }
  .fact:last-child { border-right: 0; }
  .k { font-size: 12px; color: var(--muted); margin-bottom: 2px; }
  .v { font-size: 16px; font-weight: 600; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
  .row { margin-top: 8px; padding: 9px 14px; background: var(--card); border: 1px solid var(--line); border-radius: 10px; }
  .row .v { font-size: 14px; font-weight: 400; line-height: 1.5; }
  .row .v.strong { font-weight: 600; }
  .muted { color: var(--muted); }
  /* Persistence cookie match indicator */
  .badge { display: table; margin-top: 6px; font-size: 12px; font-weight: 600; padding: 3px 10px; border-radius: 999px; }
  .row .badge { display: inline-block; margin: 0 0 0 10px; vertical-align: 1px; }
  .badge.ok { background: #dcfce7; color: #15803d; }
  .badge.warn { background: #fef3c7; color: #b45309; }
  /* Request header table */
  details.panel > summary { display: flex; align-items: center; gap: 8px; margin-bottom: 0; cursor: pointer; list-style: none; user-select: none; }
  details.panel > summary::-webkit-details-marker { display: none; }
  details.panel > summary::before { content: ""; width: 6px; height: 6px; border-right: 2px solid currentColor; border-bottom: 2px solid currentColor; transform: rotate(-45deg); transition: transform 0.15s; }
  details.panel[open] > summary::before { transform: rotate(45deg); }
  details.panel > summary:hover { color: var(--text); }
  .headers { margin-top: 10px; background: var(--card); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
  .headers table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .headers td { padding: 5px 14px; border-top: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
  .headers tr:first-child td { border-top: 0; }
  .headers td:first-child { width: 210px; color: var(--muted); white-space: nowrap; }
  /* Member images; each is a separate request to the pool */
  .images { margin-top: 16px; }
  /* Tiles sized so four span the section; fewer are centered at the same size */
  .logos { margin-top: 10px; padding: 0 24px; display: grid; grid-template-columns: repeat(var(--count, 3), calc((100% - 48px) / 4)); justify-content: center; gap: 16px; }
  .logos img { display: block; width: 100%; height: auto; filter: drop-shadow(0 2px 2px rgba(0,0,0,0.4)); }
  /* Single-column layout for narrow screens */
  @media (max-width: 720px) {
    .wrap { grid-template-columns: 1fr; }
    .facts { grid-template-columns: 1fr; }
    .fact { border-right: 0; border-bottom: 1px solid var(--line); }
    .fact:last-child { border-bottom: 0; }
    .ip, .pv { font-size: 38px; }
    .server { grid-template-columns: minmax(0, 1fr); }
    .l-ip { grid-row: 1; } .ip { grid-row: 2; }
    .l-port { grid-row: 3; margin-top: 8px; } .pv { grid-row: 4; }
    .l-host { grid-row: 5; margin-top: 8px; } .hn { grid-row: 6; font-size: 24px; }
    .cip { font-size: 24px; }
    .headers td:first-child { width: auto; white-space: normal; }
    .logos { padding: 0; grid-template-columns: repeat(2, calc((100% - 16px) / 2)); }
  }
</style>
</head>
<body>
<div class="wrap">
  <!-- Status panel -->
  <aside class="side">
    <div class="icon"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="<?= $isTls ? 'M8 11V7a4 4 0 0 1 8 0v4' : 'M8 11V7a4 4 0 0 1 7.5-2' ?>"/></svg></div>
    <div class="state"><?= $isTls ? 'TLS encrypted' : 'Not encrypted' ?>
      <small>This session is <?= $isTls ? '' : 'NOT ' ?>TLS/SSL encrypted.</small>
    </div>
    <div class="srv"><?= $serverLegProtocol ?> Pool Server</div>
  </aside>
  <main class="content">
    <!-- Server endpoint -->
    <div class="server">
      <div class="section l-ip">Server IP address</div>
      <div class="section l-port">Server port</div>
      <div class="section l-host">Server hostname</div>
      <div class="ip"><?= $serverAddr ?></div>
      <div class="pv"><?= $serverPort ?></div>
      <div class="hn"><?= $serverHostname ?></div>
    </div>
    <!-- Client endpoint and request line -->
    <div class="panel">
      <div class="section">Client IP address</div>
      <div class="cip"><?= $clientAddr ?></div>
      <div class="facts">
        <div class="fact"><div class="k">Client source port</div><div class="v"><?= $clientPort ?></div></div>
        <div class="fact"><div class="k">Protocol</div><div class="v"><?= $httpProtocol ?></div></div>
        <div class="fact"><div class="k">Request method</div><div class="v"><?= $requestMethod ?></div></div>
      </div>
      <div class="row"><div class="k"><?= $requestMethod ?> request string</div><div class="v"><?= $requestUri ?></div></div>
      <div class="row"><div class="k">User agent</div><div class="v"><?= $userAgent ?></div></div>
<?php if ($proxyAddr !== null): ?>
      <div class="row"><div class="k">Proxied through</div><div class="v strong"><?= $proxyAddr ?></div></div>
<?php endif; ?>
    </div>
    <!-- Member images, one tile per images/<n>.png; ?v= defeats caching of the static files -->
    <div class="images">
      <div class="section">Images served from Pool Member:</div>
      <div class="logos" style="--count: <?= max(1, count($memberImages)) ?>">
<?php foreach ($memberImages as $imageName): ?>
        <img src="images/<?= $imageName ?>?v=<?= $cacheBuster ?>" alt="">
<?php endforeach; ?>
      </div>
    </div>
    <!-- Recognized persistence cookie(s); decoded member shown when the format is public -->
    <div class="panel">
      <div class="section">Persistence cookie</div>
<?php if (!$persistenceCookies): ?>
      <div class="row"><div class="v muted">No persistence cookie detected</div></div>
<?php endif; ?>
<?php foreach ($persistenceCookies as $cookie): ?>
      <div class="facts">
        <div class="fact"><div class="k">Set by</div><div class="v"><?= $cookie['source'] ?></div></div>
        <div class="fact"><div class="k">Cookie name</div><div class="v"><?= $cookie['name'] ?></div></div>
        <div class="fact"><div class="k">Value</div><div class="v"><?= $cookie['value'] ?></div></div>
      </div>
<?php if ($cookie['decodable']): ?>
      <div class="row"><div class="k">Decoded pool member</div><div class="v strong">
<?php if ($cookie['member'] === ''): ?>
        <span class="muted">Can't decode (encrypted or other format)</span>
<?php else: ?>
        <?= $cookie['member'] ?><span class="badge <?= $cookie['isThisServer'] ? 'ok' : 'warn' ?>"><?= $cookie['isThisServer'] ? 'This server' : 'Different member' ?></span>
<?php endif; ?>
      </div></div>
<?php endif; ?>
<?php endforeach; ?>
    </div>
    <!-- Request headers as received by this member; collapsed by default -->
    <details class="panel">
      <summary class="section">Request headers received (<?= count($requestHeaders) ?>)</summary>
      <div class="headers"><table>
<?php foreach ($requestHeaders as $headerName => $headerValue): ?>
        <tr><td><?= $headerName ?></td><td><?= $headerValue ?></td></tr>
<?php endforeach; ?>
      </table></div>
    </details>
  </main>
</div>
</body>
</html>
