# Support Ticket: CDN Cache Key Configuration for X-HTTP-Method-Override

**Priority:** High
**Site:** talentbrand.comcast.com
**Category:** Security / Caching Configuration

---

Hey Pagely team,

We've received a validated vulnerability report through Comcast's Bugcrowd program identifying a cache poisoning vector on talentbrand.comcast.com. We've already shipped a plugin-level fix (v1.4.0 of our REST API Cache Poisoning Fix plugin), but there's a piece of this that only your team can address — the ARES caching layer.

## What's happening

An attacker can send a request like this:

```
GET /wp-json/?cb=123 HTTP/2
Host: talentbrand.comcast.com
X-Http-Method-Override: HEAD
```

WordPress honors that override header and treats the GET as a HEAD request — returning an empty body. If ARES caches that response using only the URL as the cache key (ignoring the `X-Http-Method-Override` header), then every subsequent legitimate GET to `/wp-json/?cb=123` gets the empty cached response. That's a denial of service on the REST API.

## What we've done on our end

Our plugin now rejects any request containing `X-HTTP-Method-Override`, `X-HTTP-Method`, or `X-Method-Override` headers with a 400 response and aggressive no-cache headers including `X-Accel-Expires: 0` and `Surrogate-Control: no-store`. We also strip those headers from `$_SERVER` before WordPress processes anything — so even if the rejection somehow fails, WordPress never sees the override.

## What we need from Pagely

The plugin-level fix depends on ARES respecting our `Cache-Control: no-store` and `Surrogate-Control: no-store` headers on 400 responses. If ARES caches error responses regardless of those headers, the poisoning still works — it just caches our 400 instead of an empty 200.

We'd like to confirm two things and request one configuration change:

**1. Does ARES honor `Cache-Control: no-store` and `Surrogate-Control: no-store` on 4xx responses?** If not, that's the core issue. Our plugin sends those headers specifically so ARES won't cache the rejection response.

**2. Can you strip `X-HTTP-Method-Override`, `X-HTTP-Method`, and `X-Method-Override` headers at the ARES/edge layer before they reach PHP?** This is the most robust fix. If ARES drops these headers before they ever hit WordPress, the attack vector disappears entirely — no matter what WordPress or our plugin does. These headers have no legitimate use case for this site.

**3. Alternatively, can these headers be added to the cache key for this site?** If stripping isn't possible, including `X-HTTP-Method-Override` in the cache key means a request with the header and one without produce separate cache entries. The poisoned entry wouldn't affect legitimate traffic.

## Context

This vulnerability affects WordPress core versions 4.7.0 through 6.3.1 (patched in 6.3.2). The core fix adds nocache headers when method override + 4xx occurs, but it doesn't prevent the override from being processed in the first place — and it doesn't help if the cache layer ignores those headers. Edge-level header stripping is the defense-in-depth layer that makes this class of attack impossible regardless of what happens in PHP.

We're happy to hop on a call if it'd be easier to walk through the specifics. Thanks for taking a look.

— Joe Taylor Jr.
Johns & Taylor
joe@johnsandtaylor.com
