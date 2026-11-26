# CI
One Depot Linux job cross-compiles all six Connector binaries, replacing six
identical checkout/Go setups. The separate publish job still verifies the exact
eight payload files, creates checksums, attests every asset and publishes only
matching release tags in the configured repository. Provenance now records
Depot as the self-hosted build provider. No runtime-test guarantee is added by
cross-compilation. Manual runs remain build-only.

The 30-minute build timeout is a protective cap for setup, six serial targets
and artifact upload. A cold Depot run has not been timed; the timeout is not
a measured completion guarantee. Manual runs build artifacts only.
