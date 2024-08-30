use sec1::pkcs8::DecodePrivateKey;

#[test]
fn generate_credential() {
    let key = p256::SecretKey::from_pkcs8_pem("-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEAqKZdZQgPVtjlEB\nfz2ItHG8oXIONenOxRePtqOQ42yhRANCAATA43gI2Ib8+qKK4YEOfNCRiNOhyHaC\nLgAvKdhHS+y6wpG3oJ2xudXagzKKbcfvUda4x0j8zR1/oD56mpm85GbO\n-----END PRIVATE KEY-----").unwrap();
    let wallet = super::wallet::generate_credential_from_key(key);
    panic!(
        "{}",
        base64::encode(serde_cbor::to_vec(&wallet.mdl).unwrap())
    );
}
