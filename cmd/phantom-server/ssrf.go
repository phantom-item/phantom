// Phantom — encrypted transport framework
// Copyright (C) 2026 The Phantom Authors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. It is distributed WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU AGPL <https://www.gnu.org/licenses/> for details.

package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

// isDisallowedTargetIP reports whether an IP must not be reached by a relayed
// connection when the SSRF guard is active. It covers loopback, link-local
// (which includes the 169.254.169.254 cloud-metadata endpoint), private
// ranges (RFC 1918 / ULA), unspecified, and multicast addresses.
func isDisallowedTargetIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.IsPrivate() {
		return true
	}
	return false
}

// resolveAllowedIP resolves target ("host:port") to a single concrete IP that
// has been verified against the SSRF guard, and returns that IP together with
// the port. The returned ipPort ("ip:port") is what callers MUST hand to Dial
// — never the original host string.
//
// This is the TOCTOU fix: previously the code resolved-and-checked in
// checkRelayTarget, then called Dial(target) which resolved a *second* time.
// Between the two resolutions a hostile DNS server could rebind the name from
// a public IP (passes the check) to 169.254.169.254 or an RFC1918 address
// (used by Dial). By resolving exactly once here, verifying that single
// result, and pinning Dial to the verified IP, the name can no longer point
// at one address for the check and another for the connection.
//
// When allowPrivate is true the guard is disabled and the original target is
// returned unchanged (Dial resolves as before).
func resolveAllowedIP(ctx context.Context, target string, allowPrivate bool) (ipPort string, err error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("invalid target %q: %w", target, err)
	}

	if allowPrivate {
		return target, nil
	}

	// Literal IP: verify directly, no DNS lookup, pin to it.
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedTargetIP(ip) {
			return "", fmt.Errorf("refusing to relay to disallowed address %s", ip)
		}
		return net.JoinHostPort(ip.String(), port), nil
	}

	// Hostname: resolve ONCE, pick the first address that is allowed, and
	// pin the connection to that exact IP. If ANY returned address is
	// disallowed we reject the whole name rather than silently picking a
	// "clean" sibling — a name that resolves to a mix of public and
	// internal addresses is treated as hostile.
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve target %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve target %q: no addresses", host)
	}
	for _, ipa := range ips {
		if isDisallowedTargetIP(ipa.IP) {
			return "", fmt.Errorf("refusing to relay to %q (resolves to disallowed address %s)", host, ipa.IP)
		}
	}
	// All resolved addresses are allowed; pin to the first.
	return net.JoinHostPort(ips[0].IP.String(), port), nil
}

// safeDialTCP resolves+verifies target under the SSRF guard and dials the
// verified IP. The dialer never sees the original hostname, so the address it
// connects to is exactly the one that passed the check.
func safeDialTCP(target string, allowPrivate bool, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ipPort, err := resolveAllowedIP(ctx, target, allowPrivate)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "tcp", ipPort)
}

// safeResolveUDP resolves+verifies target under the SSRF guard and returns the
// pinned *net.UDPAddr to dial. As with safeDialTCP the returned address is the
// verified IP, not a re-resolution of the hostname.
func safeResolveUDP(target string, allowPrivate bool) (*net.UDPAddr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ipPort, err := resolveAllowedIP(ctx, target, allowPrivate)
	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr("udp", ipPort)
}
