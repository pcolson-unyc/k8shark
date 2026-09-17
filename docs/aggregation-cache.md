# Aggregate response cache

The hub reuses identical `/api/summary` and `/api/graph` responses for up to one second from the start of computation. REST and MCP callers can therefore observe a slightly older snapshot. Percentile calculations and filtering are unchanged. The complete request URI distinguishes parameters; differently ordered equivalent parameters may miss the cache.

At most 32 responses and 4 MiB of serialized response bodies are retained in total. Oversized responses and errors are not cached. Builds are serialized across aggregate keys to bound concurrent aggregation work; this can increase latency for unrelated aggregate queries. Ingestion does not take the cache lock (it only shares the store's snapshot lock).

This benefits concurrent clients issuing identical requests. It does not eliminate work for a lone client polling more slowly than the TTL, nor change the UI polling interval or `/api/timeline`.
