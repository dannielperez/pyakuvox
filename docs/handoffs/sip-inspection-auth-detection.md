# Read-only SIP inspection authentication detection

Adds `inspect_sip_with_auth_detection` to the public operations facade. A device
rejecting Basic previously made the entire SIP inspection unavailable even though
its existing credentials worked with Digest. Only explicit Basic authentication
rejection triggers one Digest attempt. Every client disables transport retries;
a single overall deadline covers both attempts. No stored settings, credential,
flow-renewal or mutation policy changes.

Mocked tests cover Basic rejection, explicit Digest rejection, non-authentication
failure propagation and cancellation/client cleanup. A consented R29C read-only
probe confirmed Basic rejection and successful Digest inspection of identity,
configuration, registration and call state. A subsequent public-operation probe
returned READY with the same MAC; an earlier observation was TALKING, so no frozen
call or root cause is inferred.

Review and merge before consumer adoption. This operation does not repair missing
consumer inventory mappings or provide capabilities for other vendors.
