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
	"fmt"
	"net"
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

// checkRelayTarget resolves target ("host:port") and returns an error if the
// guard is active and any resolved address falls in a disallowed range.
//
// Resolving first and checking every returned address defeats the
// "domain that resolves to an internal IP" bypass: a literal IP and a
// hostname pointing at the same address are both rejected.
func checkRelayTarget(target string, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target %q: %w", target, err)
	}

	// Literal IP: check directly without a DNS lookup.
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedTargetIP(ip) {
			return fmt.Errorf("refusing to relay to disallowed address %s", ip)
		}
		return nil
	}

	// Hostname: resolve and reject if ANY result is disallowed.
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolve target %q: %w", host, err)
	}
	for _, ip := range ips {
		if isDisallowedTargetIP(ip) {
			return fmt.Errorf("refusing to relay to %q (resolves to disallowed address %s)", host, ip)
		}
	}
	return nil
}
