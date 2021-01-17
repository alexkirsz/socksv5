# socksv5

SOCKS v4a and v5 basic building blocks to build your own async SOCKS
application. See [examples/proxy](examples/proxy) for an example use case.

## Futures

This library supports futures 0.3 async traits by default.

Tokio 1 async traits support can be enabled with the `tokio`
feature. In that case, set `default-features = false` to avoid pulling in
the `futures` crate.

## TODO

- [ ] Client-side message parsing.
- [ ] Username/password and GSSAPI authentication methods.
- [ ] Documentation.
- [ ] Tests.
- [ ] Sync API.

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>