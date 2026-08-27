# Generate usable RSA GPG keys from RFC9500 test key values

[![No Maintenance Intended]][no-maintenance]

[No Maintenance Intended]: https://img.shields.io/badge/No%20Maintenance%20Intended-%F0%9F%97%99-red
[no-maintenance]: https://unmaintained.tech/

[RFC9500] introduces Public Key Cryptography keys for test or documentation
purposes.

For use with gpg/sequoia, you will need a user ID and binding self-signature
for it.

This crate uses the
[`sequoia_openpgp`](https://docs.rs/sequoia-openpgp/1.12.0/sequoia_openpgp)
crate to generate armored exports of the public and private keys, and with a
little modification exporting them as binary encoded byte streams is possible
too.


```no_run
# use gen_rfc9500_gpg_keys::*;
# fn run() {
let mut stdout = std::io::stdout();
let uid: UserID = "user@example.org".into();
let cert = generate_rsa_cert(Some(uid)).unwrap();
write_private_armored_key_block(Message::new(&mut stdout), &cert).unwrap();
write_public_armored_key_block(Message::new(&mut stdout), &cert).unwrap();
# }
```

[RFC9500]: <https://datatracker.ietf.org/doc/rfc9500/>
