# Nullifier Reuse Across Repeated Withdrawals

The withdraw circuit outputs the nullifier input unchanged. When a second
withdrawal step is wired to reuse the prior nullifier output, the chain
produces identical nullifiers across withdrawals.

This violates the expectation that each withdrawal consumes a unique
nullifier and enables double-withdrawal scenarios in multi-step workflows.
