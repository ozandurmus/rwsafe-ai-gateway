# tools/proxysg

Helpers the Product Owner runs on the machine that holds ProxySG exports (`docs/operations/PROXYSG_PHASE0_GUIDE.md`).
Raw exports never enter the repository and are never read by an agent; only the aggregate output is shared.

- `access_log_shapes.py`: aggregate-only shapes of a W3C access log (counts, buckets, vendor platform labels). Refuses to
  print if an address- or e-mail-shaped value would reach the output.
- `test_access_log_shapes.py`: unit tests on a synthetic log built at runtime (`python3 -m unittest tools/proxysg/test_access_log_shapes.py`).
