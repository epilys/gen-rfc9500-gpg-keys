// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

use gen_rfc9500_gpg_keys::*;
use openpgp::{PacketPile, parse::Parse};

// NOTE: the self signature has a random salt, so we need to process the parsed
// `Cert` certificates to remove it- Otherwise comparing for equality will fail.

// [`identity_filter`](https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/struct.Cert.html#filtering-certificates)
fn identity_filter(cert: Cert) -> Cert {
    // Iterate over all the Cert components, pushing packets we
    // want to keep into the accumulator.
    let mut acc = Vec::new();

    // Primary key and related signatures.
    let c = cert.primary_key();
    acc.push(c.key().clone().into());
    //for s in c.self_signatures() {
    //    acc.push(s.clone().into())
    //}
    for s in c.certifications() {
        acc.push(s.clone().into())
    }
    for s in c.self_revocations() {
        acc.push(s.clone().into())
    }
    for s in c.other_revocations() {
        acc.push(s.clone().into())
    }

    // UserIDs and related signatures.
    for c in cert.userids() {
        acc.push(c.userid().clone().into());
        //for s in c.self_signatures() {
        //    acc.push(s.clone().into())
        //}
        for s in c.approvals() {
            acc.push(s.clone().into())
        }
        for s in c.certifications() {
            acc.push(s.clone().into())
        }
        for s in c.self_revocations() {
            acc.push(s.clone().into())
        }
        for s in c.other_revocations() {
            acc.push(s.clone().into())
        }
    }

    // UserAttributes and related signatures.
    for c in cert.user_attributes() {
        acc.push(c.user_attribute().clone().into());
        //for s in c.self_signatures() {
        //    acc.push(s.clone().into())
        //}
        for s in c.approvals() {
            acc.push(s.clone().into())
        }
        for s in c.certifications() {
            acc.push(s.clone().into())
        }
        for s in c.self_revocations() {
            acc.push(s.clone().into())
        }
        for s in c.other_revocations() {
            acc.push(s.clone().into())
        }
    }

    // Subkeys and related signatures.
    for c in cert.keys().subkeys() {
        acc.push(c.key().clone().into());
        //for s in c.self_signatures() {
        //    acc.push(s.clone().into())
        //}
        for s in c.certifications() {
            acc.push(s.clone().into())
        }
        for s in c.self_revocations() {
            acc.push(s.clone().into())
        }
        for s in c.other_revocations() {
            acc.push(s.clone().into())
        }
    }

    // Unknown components and related signatures.
    for c in cert.unknowns() {
        acc.push(c.unknown().clone().into());
        //for s in c.self_signatures() {
        //    acc.push(s.clone().into())
        //}
        for s in c.certifications() {
            acc.push(s.clone().into())
        }
        for s in c.self_revocations() {
            acc.push(s.clone().into())
        }
        for s in c.other_revocations() {
            acc.push(s.clone().into())
        }
    }

    // Any signatures that we could not associate with a component.
    for s in cert.bad_signatures() {
        acc.push(s.clone().into())
    }

    // Finally, parse into Cert.
    Cert::try_from(acc).unwrap()
}

#[test]
fn test_output() {
    let mut secret_key_output = vec![];
    let uid: UserID = "user@example.org".into();
    let cert = generate_rsa_cert(Some(uid)).unwrap();
    write_private_armored_key_block(Message::new(&mut secret_key_output), &cert).unwrap();
    let secret_packet_pile = PacketPile::from_file("./tests/secret_key_armor.txt").unwrap();
    let secret_cert_truth = Cert::try_from(secret_packet_pile).unwrap();
    let secret_cert = Cert::try_from(PacketPile::from_bytes(&secret_key_output).unwrap()).unwrap();
    assert_eq!(
        identity_filter(secret_cert_truth),
        identity_filter(secret_cert)
    );
    let mut public_key_output = vec![];
    write_public_armored_key_block(Message::new(&mut public_key_output), &cert).unwrap();
    let public_packet_pile = PacketPile::from_file("./tests/public_key_armor.txt").unwrap();
    let public_cert_truth = Cert::try_from(public_packet_pile).unwrap();
    let public_cert = Cert::try_from(PacketPile::from_bytes(&public_key_output).unwrap()).unwrap();
    assert_eq!(
        identity_filter(public_cert_truth),
        identity_filter(public_cert)
    );
}
