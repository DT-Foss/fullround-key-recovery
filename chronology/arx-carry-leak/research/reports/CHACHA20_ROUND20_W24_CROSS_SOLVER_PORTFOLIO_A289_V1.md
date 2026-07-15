# A289 — ChaCha20-R20 W24 cross-solver portfolio

Evidence stage: **FULLROUND_R20_W24_CROSS_SOLVER_BUDGET_BOUNDARY**

- Standard rounds plus feed-forward: **20**
- Unknown key bits: **24**
- Public output: **8 blocks / 4096 bits**
- Solvers: **Kissat + CryptoMiniSat**
- Candidate-domain enumeration: **none**
- Winner: **None**

## Solver arms

```json
[
  {
    "arm": "cryptominisat_bfs_default",
    "command_sha256": "35532f5f0e5a60c313a27f0b383bb57fa683f7188cd299584ce2f948d31e61e1",
    "elapsed_seconds": 7690.48851920804,
    "returncode": 15,
    "solver": "cryptominisat_default",
    "source_A287_CNF_arm": "bfs_far_sat",
    "status": "unknown",
    "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "stdout_sha256": "4a52c9a8b31d6fc86b80dd052c5c856427974d7b1f25c502df82270e6c3aa3ab",
    "terminated_after_sibling_sat": false
  },
  {
    "arm": "kissat_base_sat",
    "command_sha256": "af83ded8b8736e27fd0962510753e03368b36ecb5998cb0d020f58bece648223",
    "elapsed_seconds": 7690.487147042062,
    "returncode": 0,
    "solver": "kissat_sat",
    "source_A287_CNF_arm": "base_default",
    "status": "unknown",
    "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "stdout_sha256": "2c4c866c90a863846ecab6e6bac416700035e3791b12ca7bb7ce17b07a49ddf5",
    "terminated_after_sibling_sat": false
  }
]
```

## Next AI-native gap

`A287_A289_boundary_conditioned_exact_W24_partition`
