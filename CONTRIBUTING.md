# Contributing

Thanks for helping. A few rules keep a security tool trustworthy:

1. **Standard library only.** Every dependency is code users have to trust.
2. **Never overclaim.** A check that could not run must say so where its result
   would have been. Do not add an ATT&CK technique to `hunt.COVERAGE` unless a
   shipped collector actually looks for it.
3. **Fetched content may only add suspicion.** Nothing from a feed, an article
   or a model may approve a process, clear a finding or lower a severity.
4. **No key values, ever.** The input monitor records injected-event metadata
   and per-minute counts, not what was typed.
5. **Tests with every change**, including the failure path:
   `python3 -m unittest discover -s tests`.

## Developer Certificate of Origin

Contributions are accepted under the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
Sign off every commit to certify you wrote it or have the right to submit it
under the Apache License 2.0:

```
git commit -s -m "Describe the change"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line. Pull requests
with unsigned commits cannot be merged.
