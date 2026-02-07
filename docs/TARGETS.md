# zk0d Targets (Discovery Set)

**Single success metric:** discoveries on `/media/elements/Repos/zk0d`

This document lists the **target circuits** for evidence runs.  
The machine-readable list used by the batch runner is in:

`targets/zk0d_targets.yaml`

---

## How to Use

1. Create a campaign YAML per target (manual invariants required).
2. Enable the target in `targets/zk0d_targets.yaml`.
3. Run the batch runner:

```bash
scripts/run_ai_campaign.sh --targets targets/zk0d_targets.yaml
```

---

## Initial Target Set (Example)

| Name | Circuit Path | Framework | Campaign YAML |
|---|---|---|---|
| tornado_withdraw | `zk0d/cat3_privacy/tornado-core/circuits/withdraw.circom` | circom | `campaigns/zk0d/tornado_withdraw.yaml` |
| semaphore | `zk0d/cat3_privacy/semaphore/packages/circuits/src/semaphore.circom` | circom | `campaigns/zk0d/semaphore.yaml` |
| iden3_authv3 | `zk0d/cat3_privacy/iden3/.../authV3.circom` | circom | `campaigns/zk0d/iden3_authv3.yaml` |

> Update this list as you add more targets.  
> The batch runner will only execute entries marked `enabled: true`.
