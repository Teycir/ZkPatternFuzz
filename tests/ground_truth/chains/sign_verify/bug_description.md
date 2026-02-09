# Signature Verification Ignores Message

The verify circuit only checks that signature components are non-zero and
ignores the message input. As a result, a signature created for one message
will still verify for a different message.

The chain detects this by verifying the same signature against a tampered
message and expecting verification to fail.
