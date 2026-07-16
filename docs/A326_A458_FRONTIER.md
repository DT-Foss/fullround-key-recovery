# A326--A458 full-round ChaCha20 W52 Reader frontier

This record binds the recovery repository to the completed public W52 schedule
frontier in
[`DT-Foss/f8-causal-cryptanalysis`](https://github.com/DT-Foss/f8-causal-cryptanalysis/tree/676ee0d6523351347b75907b151c5c4b605061ac).
The source commit is
`676ee0d6523351347b75907b151c5c4b605061ac`; its release verifier authenticates
935 files and five complete 16,777,216-cell pair streams.

## Completed schedule results

| Attempt | Completed result |
|---|---|
| A454 | Exhaustive 248-schedule comparison selects `BOOHH`; remaining-96 aggregate/minimum gains are `0.471700940510`/`0.160759080631` bit. |
| A456 | Exhaustive 878-schedule, 86-orbit frequency ray selects `BOOOOOOHHHHHH`; gains rise to `0.489437610231`/`0.176347721941` bit. The complete pair stream SHA-256 is `9a3af1cfb71f96d186815086170127cd5340e7ac102a5fe9dc65414c14df7352`. |
| A458 | Exhaustive 405-schedule, 18-orbit B1/B0 extension selects `OOOOOOOOHHHHHHHHHHHHHHHBOOOOOOO`; gains rise again to `0.495787645250`/`0.205050504927` bit. The complete pair stream SHA-256 is `5220aa319ab75f7e5e77717802f248512ecdb04531a5d660ac48302f428a1138`. |

Every released schedule is a complete permutation of the `2^24` W52 pair-cell
domain. A456 and A458 each satisfy all exact declared component proposal bounds
over all 16,777,216 cells, retain positive gain on all eight fixed blocks, and
use zero W52 labels, zero feature or model refits, and zero production candidate
assignments.

## Recovery boundary

A455 and A457 are hash-bound eight-worker executors over the complete `2^52`
residual domain. Both protocols were frozen with production disabled and zero
candidate assignments. No live worker progress, filter outcome, stop object, or
secret recovery result is present in either public repository.

The 13 complete-domain and 24 strict-subset recovery executions summarized in
this repository remain the closed recovery set. A456 and A458 advance the W52
target-blind execution schedule; they are schedule results, not additional
recovery executions.

## Immutable anchors

| Artifact | SHA-256 |
|---|---|
| A456 result JSON | `8a06661bd6ace82fc9b6854eb4158ddc8a92a47563d71d4aee1cf47707cbbc88` |
| A456 AI-native Causal graph | `ef9024b9c5644958ca4a3f7ebff8ec16c2a448867f4a7e86445b83e07390213d` |
| A456 personal Reader readback | `37898bba41c518b0f07c7c415a32ecc9afe7264a3936003b14b60513f7ec6a32` |
| A458 result JSON | `6363cccb36acdbeb04cff12e77e40ccabac481e06394ca3fe3035fd9ff21fa7c` |
| A458 AI-native Causal graph | `fa1b20018c48f640fca9ad7034cb70c7f6a98da1a6a32dd62716a4f19f1ffcd8` |
| A458 personal Reader readback | `753dbc6e1a08e057cabb0fe7131678f1156d11b338694510f2d7ae4e2da5f837` |

The source repository reproduces the complete gate with:

```bash
python scripts/verify_a326_a458_frontier.py
python -m pytest -q tests/test_a326_a458_frontier_release.py
python scripts/validate_causal_artifacts.py
```

Expected frontier line:

```text
A326--A458 frontier verification: OK (935 files)
```
