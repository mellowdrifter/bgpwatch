# BGPWatch gRPC API Documentation

This directory contains the documentation for the BGPWatch gRPC API. The service is defined in [proto/bgpwatch.proto](../proto/bgpwatch.proto).

By default, the daemon listens for gRPC connections on port **1179**.

---

## Service: `bgpwatch.BGPWatch`

### 1. `GetTotals`
Returns the aggregate number of unique prefixes in the global RIB and the total number of paths received across all peers.

*   **Input**: None
*   **Command**:
    ```bash
    grpcurl -plaintext localhost:1179 bgpwatch.BGPWatch/GetTotals
    ```
*   **Output**:
    *   `ipv4_count`: Unique IPv4 prefixes in the global RIB.
    *   `ipv6_count`: Unique IPv6 prefixes in the global RIB.
    *   `total_ipv4_paths`: Total IPv4 paths across all peers.
    *   `total_ipv6_paths`: Total IPv6 paths across all peers.

### 2. `GetRoute`
Performs a single-prefix lookup. Supports Longest Prefix Match (LPM) for IP addresses and Exact Match for CIDR prefixes.

*   **Input**: `address` (string)
*   **Command (LPM)**:
    ```bash
    grpcurl -plaintext -d '{"address": "1.1.1.1"}' localhost:1179 bgpwatch.BGPWatch/GetRoute
    ```
*   **Command (Exact)**:
    ```bash
    grpcurl -plaintext -d '{"address": "1.1.1.0/24"}' localhost:1179 bgpwatch.BGPWatch/GetRoute
    ```
*   **Output**: A `RouteLookupResponse` containing a `found` boolean and the `route` metadata if successful.

### 3. `GetRoutes`
Queries all connected peers for a specific route. This allows you to see path diversity (different AS paths or attributes) for the same prefix across different upstream providers.

*   **Input**: `address` (string)
*   **Command**:
    ```bash
    grpcurl -plaintext -d '{"address": "8.8.8.8"}' localhost:1179 bgpwatch.BGPWatch/GetRoutes
    ```
*   **Output**: A list of `Route` objects, one for each peer that has a matching entry.

### 4. `GetPrefixesByOrigin` (Lightweight)
Returns a list of prefixes originated by a specific Autonomous System (ASN). This is highly efficient and returns only the CIDR strings.

*   **Input**: `asn` (uint32)
*   **Command**:
    ```bash
    grpcurl -plaintext -d '{"asn": 13335}' localhost:1179 bgpwatch.BGPWatch/GetPrefixesByOrigin
    ```
*   **Output**: A simple list of prefix strings. Use this when you only need to know *what* is being announced.

### 5. `GetRoutesByOrigin` (Detailed)
Returns full route metadata for every prefix originated by a specific ASN. 

*   **Input**: `asn` (uint32)
*   **Command**:
    ```bash
    grpcurl -plaintext -d '{"asn": 13335}' localhost:1179 bgpwatch.BGPWatch/GetRoutesByOrigin
    ```
*   **Output**: A list of `Route` objects including AS path, communities, local pref, etc. **Warning**: This can be a very large response for ASNs with many prefixes (e.g., Akamai or Cloudflare).

### 6. `GetPrefixesByAsPath`
Performs a regular expression search on the AS path. Supports Cisco-style regex, including the `_` (underscore) delimiter.

*   **Input**: `regex` (string)
*   **Command (Cisco-style)**:
    ```bash
    # Paths originating from AS 13335
    grpcurl -plaintext -d '{"regex": "_13335$"}' localhost:1179 bgpwatch.BGPWatch/GetPrefixesByAsPath
    
    # Paths passing through AS 1299
    grpcurl -plaintext -d '{"regex": "_1299_"}' localhost:1179 bgpwatch.BGPWatch/GetPrefixesByAsPath
    ```
*   **Output**: A list of `Route` objects matching the pattern.

### 7. `GetSystemStats`
Returns real-time memory usage of the daemon and statistics for each connected peer.

*   **Input**: None
*   **Command**:
    ```bash
    grpcurl -plaintext localhost:1179 bgpwatch.BGPWatch/GetSystemStats
    ```
*   **Output**: Memory metrics (Heap, Sys, RAM) and per-peer advertisement/withdrawal counters.

### 8. `GetMasks`
Returns the distribution of subnet mask lengths for IPv4 and IPv6.

*   **Input**: None
*   **Command**:
    ```bash
    grpcurl -plaintext localhost:1179 bgpwatch.BGPWatch/GetMasks
    ```
*   **Output**: Maps of mask length (e.g., 24) to the number of prefixes with that length.
