# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-11

### Added
- Initial release
- Strip `X-HTTP-Method-Override`, `X-HTTP-Method`, and `X-Method-Override` headers from REST API requests
- Add `Vary` headers to REST API responses for cache differentiation
- Add `Cache-Control: no-cache` headers for unauthenticated REST API requests
- Security logging when `WP_DEBUG` is enabled
- Support for common proxy headers when logging client IPs (Cloudflare, X-Forwarded-For, X-Real-IP)

### Security
- Mitigates cache poisoning vulnerability (CVE pending) where attackers could break REST API for unauthenticated users
