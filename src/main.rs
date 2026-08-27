// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later

use gen_rfc9500_gpg_keys::*;

fn main() -> Result<()> {
    env_logger::init();

    let mut stdout = std::io::stdout();
    let uid: UserID = "user@example.org".into();
    let cert = generate_rsa_cert(Some(uid)).unwrap();
    write_private_armored_key_block(Message::new(&mut stdout), &cert).unwrap();
    write_public_armored_key_block(Message::new(&mut stdout), &cert).unwrap();

    Ok(())
}
