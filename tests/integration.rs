// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

use gen_rfc9500_gpg_keys::*;
use openpgp::{PacketPile, parse::Parse};

use sequoia::Sequoia;
use sequoia::prompt::Cancel;

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

#[test]
fn test_sign_and_verify() {
    const PUBKEY: &[u8] = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nxsBNBAAAAAABCACw+egZQ6eumJKq3hfKfED4dE/tL4FI5sjqont9ABVI+1GSqyi1\r\nbFBgsRjM0THllIdMbKmJtWwnKW8J+5OgNN8y6Xxv8JmM/Y5vQt2lis0fqXmG8UTz\r\n0VTWdlAXXmhUs6lSADvAaIe4RVrCsZ97L3ZQTryY7JRVcbB4khUN3Gp0yg+801SX\r\nzoFTTa+UGIRLE66jH51aa5VXu99hnv1OiH8tQrjdi8mH6uG/icq4XuIeNWMF32wH\r\nqIOOPvQcWV3M5D2vxJEj702Ku6k9OQXkAo17qRSEonWW4HtLbtmS8He1JNPc/n3d\r\nVUm+fM6NoDXPoLP7j55G9zKyqGtGAWXAj1MTABEBAAHNEHVzZXJAZXhhbXBsZS5v\r\ncmfCwLsEEwEKAG8FggAAAAAJEMwuljyZl1FjRxQAAAAAAB4AIHNhbHRAbm90YXRp\r\nb25zLnNlcXVvaWEtcGdwLm9yZ56lfAkULy8QwPhEcrlasB0N4oBn0im6wT4mwiAT\r\nHZjBFiEErtwR+84tdGv4v3FmzC6WPJmXUWMAAI1tCACHuuzmgEqoIrk3QZaZwReK\r\nzNOs/einaVqItsI38AWLlyruwM+5IBYskBx7EjPk/yBMyWSR0X9WxiBpuXrxcpql\r\nqU8NUYXEEQeo57921ol9FnAWEp2Aqo11O5r26P7XDv+IDj0qX3+uAjSwmH0wJvrH\r\nloWCBooVuEaMX0VeMcuVXzqGZtHMp8DB1sWJMof1Znhrx3N/tAV+RnYdzuhBIgci\r\nUZRQ5MLqrt8ks9fyIAL3btRS2nsBGdyTbzFxVkoxc4yRx2ZiNiB8OlMzGk5YoiOf\r\ntkKM/mF6HTpfppF0CIhuo/q29lUCSpQDmfjksawPq3Z6LGaqw4vsj5fHEo7k47Nu\r\n=1oV4\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n";
    const PRIVKEY: &[u8] = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n\r\nxcLYBAAAAAABCACw+egZQ6eumJKq3hfKfED4dE/tL4FI5sjqont9ABVI+1GSqyi1\r\nbFBgsRjM0THllIdMbKmJtWwnKW8J+5OgNN8y6Xxv8JmM/Y5vQt2lis0fqXmG8UTz\r\n0VTWdlAXXmhUs6lSADvAaIe4RVrCsZ97L3ZQTryY7JRVcbB4khUN3Gp0yg+801SX\r\nzoFTTa+UGIRLE66jH51aa5VXu99hnv1OiH8tQrjdi8mH6uG/icq4XuIeNWMF32wH\r\nqIOOPvQcWV3M5D2vxJEj702Ku6k9OQXkAo17qRSEonWW4HtLbtmS8He1JNPc/n3d\r\nVUm+fM6NoDXPoLP7j55G9zKyqGtGAWXAj1MTABEBAAEAB/9BGIsgz9vbws8f/nUt\r\ny6pyOQY1LiYV1J3OgFl/zwoFQDvvAPoGUYL3Lez7WW9LDOj/WXC68HqJpRnsyBay\r\n9P+sUGmvGwa/73v2vNeeToHIxaOn2RMNw8+62uX20oj5ruP2/5L64Pga9Ze+yWrp\r\n+rlALNX+QfcFvr20e7c20/5sWlHg4gcyqXteRsHL2ybXSFTGtmBK7UY3Nf+QdgRl\r\nV8r5Sb9EiJXCBDLB4JwBTqdWYENPGg874pS6vF1TDmoQIT9TtgN1/ISnVz8q8SFV\r\nhPW0vabU6PnhenjZfne4baShhGR1MYp6EKVhAU7/ojqB7Fbp5BCd74yz95ciP32N\r\nDUNRBADM8eW7kMjpeB6nW+vxC8JS4R6wI6AmDxiHVSpWhj9KZCHoxgC/Uj1ssbCt\r\nvdZb/uSoigN+PRpBXlu5VkjaWgyia1T0pjlIUiw9X4m5SnLv/5UTTVlAzkV1jzCJ\r\ngJCJVliO71dbPkvEw2jP6BPunCUsKwLg35HxqgGTjThoXWC6bwQA3RBXAjgvIys2\r\ngfU3keImF8e/TprLge1I2vbWmV2j6rZCg5r/AS0upii5CvJ5/T5vfJPNgPBy8B/y\r\nRDs+6PJO1GmnlhOkG9JAIPkv0RBZvR0PMBtbp6nTY3yo1lwamBVBfY6rc0sLTzos\r\nZh2aGoLzrHNMQFMGaauORzBFpY5lU50D/AqB2KYYMUqAOvYcBnEfLDmyZv9BTVNH\r\nbR2lKkMYqv5LlvDaBxVfilE02riO4p6BaAdvzXjKeRrGNEKoHNBpOSfYCOM16NjL\r\n8hIZB1CaV3WbT5oY+jp7Mzd57d56RZOE+ERK2uz/7JX9VSsM/LbH9pJibd4e8mik\r\nDS9ntciqOH/3QwrNEHVzZXJAZXhhbXBsZS5vcmfCwLsEEwEKAG8FggAAAAAJEMwu\r\nljyZl1FjRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ56l\r\nfAkULy8QwPhEcrlasB0N4oBn0im6wT4mwiATHZjBFiEErtwR+84tdGv4v3FmzC6W\r\nPJmXUWMAAI1tCACHuuzmgEqoIrk3QZaZwReKzNOs/einaVqItsI38AWLlyruwM+5\r\nIBYskBx7EjPk/yBMyWSR0X9WxiBpuXrxcpqlqU8NUYXEEQeo57921ol9FnAWEp2A\r\nqo11O5r26P7XDv+IDj0qX3+uAjSwmH0wJvrHloWCBooVuEaMX0VeMcuVXzqGZtHM\r\np8DB1sWJMof1Znhrx3N/tAV+RnYdzuhBIgciUZRQ5MLqrt8ks9fyIAL3btRS2nsB\r\nGdyTbzFxVkoxc4yRx2ZiNiB8OlMzGk5YoiOftkKM/mF6HTpfppF0CIhuo/q29lUC\r\nSpQDmfjksawPq3Z6LGaqw4vsj5fHEo7k47Nu\r\n=tzjb\r\n-----END PGP PRIVATE KEY BLOCK-----\r\n";
    //let sq = Sequoia::builder().stateless().build().unwrap();
    let tempdir = tempfile::tempdir().unwrap();
    {
        #[allow(unused_unsafe)]
        unsafe {
            std::env::set_var("HOME", tempdir.path());
        }
        #[allow(unused_unsafe)]
        unsafe {
            std::env::set_var("SEQUOIA_HOME", tempdir.path());
        }
        #[allow(unused_unsafe)]
        unsafe {
            std::env::set_var("GNUPGHOME", tempdir.path());
        }

        #[allow(unused_unsafe)]
        unsafe {
            std::env::set_var("GPG_AGENT_INFO", "");
        }
    }
    let sq = Sequoia::new(Cancel::new()).unwrap();

    let sec_key = String::from_utf8_lossy(&PRIVKEY).parse().unwrap();
    dbg!(sq.home());
    let local_trust_root = sq.local_trust_root().unwrap();
    let outcome = sq
        .pki_certify()
        .certify(
            &local_trust_root,
            &sec_key,
            &sec_key
                .userids()
                .map(|u| u.component().clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    dbg!(&outcome);
    dbg!(&outcome.certifications().collect::<Vec<_>>());
    let sec_key = outcome.into_cert();
    let mut ser = vec![];
    use openpgp::serialize::Marshal;
    sec_key.as_tsk().serialize(&mut ser).unwrap();
    std::fs::write(tempdir.path().join("sec_tsk.cert"), &ser).unwrap();
    std::process::Command::new("sq")
        .arg("inspect")
        .arg("--certifications")
        .arg("--dump-bad-signatures")
        .arg(&tempdir.path().join("sec_tsk.cert"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output()
        .unwrap();
    let key_import_outcome = dbg!(sq.key_import().import_key(sec_key)).unwrap();
    dbg!(&key_import_outcome);
    let lsec_key = sq
        .lookup()
        .lookup_one(
            "AEDC11FBCE2D746BF8BF7166CC2E963C99975163"
                .parse::<openpgp::Fingerprint>()
                .unwrap(),
        )
        .unwrap();
    ser.clear();
    lsec_key.as_tsk().serialize(&mut ser).unwrap();
    use openpgp::policy::{HashAlgoSecurity, Policy, StandardPolicy};

    let ref sp = StandardPolicy::new();
    //dbg!(
    //    lsec_key
    //        .with_policy(sp, None)
    //        .unwrap()
    //        .userids()
    //        .collect::<Vec<_>>()
    //);
    //dbg!(
    //    lsec_key
    //        .with_policy(sp, None)
    //        .unwrap()
    //        .userids()
    //        .nth(0)
    //        .unwrap()
    //        .certifications()
    //        .collect::<Vec<_>>()
    //);

    {
        use openpgp::parse::stream::*;
        use openpgp::parse::{PacketParser, Parse, stream::*};
        use openpgp::policy::StandardPolicy;
        use openpgp::{Cert, KeyHandle, Packet, Result};

        let signature = "-----BEGIN PGP SIGNATURE-----\r\n\r\niQEzBAABCAAdFiEErtwR+84tdGv4v3FmzC6WPJmXUWMFAmqtfCgACgkQzC6WPJmX\r\nUWMReAgAhPQVrllRzrYEb9i6wdAoooXt2iShiSevw8x5in8PvC9PCQapAuHrgSBe\r\nqYKSmIyQhDtSwJAS0uqlygoXcyEqKMLmg/UpYJcUvy2Z2cvCkTGrrr5Sl7ql2XZi\r\nBsyjqyIa92NCq1Z3K/rhcIDm6X791jeuFrx+3DgaYk0stRIuKovPtm3b63KiBMkx\r\nhavgaZqzmshYJAeoz3zrRHBGFnUT5kFRH6utooYtFOnSwKsT/1FZGvtXnU97x728\r\n5/LYw8LbXxfQIMqdCmQ58gZqg8OYTGbL/zvjyIzN0RflYdc3fqJQlH4oe1s2AVbD\r\n0X9g2ivzoD58S+C2F2ih1kOWgaawmg==\r\n=PN6V\r\n-----END PGP SIGNATURE-----";
        let signed_part = "Content-Transfer-Encoding: 8bit\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\nfoobar\r\n\r\n";

        // Sanity check: Verify with gpg binary first
        let sig_file = tempdir.path().join("sig");
        let signed_file = tempdir.path().join("mime");

        std::fs::write(&sig_file, &signature).unwrap();
        std::fs::write(&signed_file, signed_part).unwrap();

        {
            let mut import = std::process::Command::new("gpg")
                .arg("--import")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .unwrap();
            import.stdin.take().unwrap().write_all(PUBKEY).unwrap();
            let import_output = import.wait_with_output().unwrap();

            assert!(
                import_output.status.success(),
                "gpg --import exited with {import_output:?}"
            );
            dbg!(import_output);
        }
        let output = std::process::Command::new("gpg")
            .arg("--verify")
            .arg(&sig_file)
            .arg(&signed_file)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "gpg --verify exited with {output:?}"
        );
        dbg!(output);
        #[derive(Debug)]
        struct Helper {
            packets: Vec<Packet>,
        }
        impl VerificationHelper for Helper {
            // ...
            fn inspect(&mut self, pp: &PacketParser<'_>) -> Result<()> {
                self.packets.push(pp.packet.clone());
                Ok(())
            }
            fn get_certs(&mut self, ids: &[KeyHandle]) -> Result<Vec<Cert>> {
                dbg!(ids);
                let sq = Sequoia::new(Cancel::new()).unwrap();
                let lsec_key = sq
                    .lookup()
                    .lookup_one(
                        "AEDC11FBCE2D746BF8BF7166CC2E963C99975163"
                            .parse::<openpgp::Fingerprint>()
                            .unwrap(),
                    )
                    .unwrap();
                Ok(vec![lsec_key])
            }

            fn check(&mut self, structure: MessageStructure) -> Result<()> {
                for (i, layer) in structure.into_iter().enumerate() {
                    match layer {
                        MessageLayer::Encryption { .. } if i == 0 => (),
                        MessageLayer::Compression { .. } if i == 1 => (),
                        MessageLayer::SignatureGroup { ref results } if i == 1 || i == 2 => {
                            if !results.iter().any(|r| r.is_ok()) {
                                return Err(sequoia::anyhow::anyhow!("No valid signature"));
                            }
                        }
                        other => {
                            dbg!(&other);
                            return Err(sequoia::anyhow::anyhow!("Unexpected message structure"));
                        }
                    }
                }
                Ok(())
            }
        }

        let mut v = DetachedVerifierBuilder::from_bytes(&signature)
            .unwrap()
            .mapping(true)
            .with_policy(sp, None, Helper { packets: vec![] })
            .unwrap();
        dbg!(v.verify_bytes(&signed_part));
        let helper = v.into_helper();
        dbg!(&helper);
        _ = tempdir.close();
    }
}
