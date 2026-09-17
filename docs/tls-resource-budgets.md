# TLS capture resource budgets

Each worker admits up to 4096 TLS streams and retains up to 64 MiB of payload
bytes across their read/write queues, including partially consumed chunks.
The source's existing 4096-record queue is separately bounded; these limits
are not a total process RSS ceiling and exclude parser state and kernel maps.

New streams above the cap are rejected. An existing direction exceeding its
byte or queue limit drains its valid prefix and ends at EOF; its tail is not
spliced across the missing bytes. Idle streams expire on the existing sweep.
Parser completion discards remaining queued data and returns its byte budget.

`k8shark_worker_tls_budget_drops_total{node=...}` counts records rejected at the
stream or byte limits. The same count appears in worker stats as `tlsBudgetDrops`.
