# Philosophy

## Why Phantom Exists

Phantom is a systems engineering exercise — to understand modern encrypted
transport architecture from the ground up, not to ship a product.

The goal is to build something we are proud of technically, not something
that gets the most stars.

## Core Principles

- Clean architecture over feature bloat
- Each layer has exactly one responsibility
- Transport and policy are separate concerns
- Observability is not optional
- If it cannot be tested, it should not exist

## Compatibility Philosophy

Trojan protocol compatibility is an entry point, not an identity.
Phantom borrows the wire format for interoperability, but the internal
architecture is fully independent. The URI scheme, config model, and
session lifecycle are all Phantom-native.

## What We Will Not Do

- Region-specific censorship evasion heuristics
- Hardcoded fingerprint databases for specific networks
- Commercial panel, reseller, or multi-node cluster management
- Streaming unlock optimizations or residential IP routing
- Traffic forgery targeting specific inspection systems

## A Note on Scope

Phantom is intentionally transport-only. Routing, ACLs, and policy belong
in the layer above — tools like clash or sing-box are better suited for that.
Keeping Phantom focused keeps it maintainable.
