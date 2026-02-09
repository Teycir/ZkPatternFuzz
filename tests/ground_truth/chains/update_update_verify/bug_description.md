# Root Update Ignores Leaf Across Multiple Updates

The update_root circuit hashes oldRoot with pathIndex and ignores the leaf.
When two updates use the same oldRoot and pathIndex but different leaves,
both updates produce the same newRoot.

A follow-up verify step then consumes the second root, and the chain
assertion detects that the first and third-step roots should diverge.
