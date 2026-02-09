# Root Propagation Breaks Across Update and Verify

The update_root circuit computes newRoot using oldRoot and pathIndex instead
of the leaf. The verify_root circuit recomputes the root from leaf and
pathIndex, so the two roots diverge.

The chain detects this by asserting that update_root.newRoot must equal
verify_root.computedRoot.
