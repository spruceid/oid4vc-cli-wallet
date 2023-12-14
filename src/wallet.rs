use std::time::Duration;

use crate::Wallet;
use isomdl180137::isomdl::{
    definitions::{
        namespaces::org_iso_18013_5_1::OrgIso1801351,
        traits::{FromJson, ToNamespaceMap},
        CoseKey, DeviceKeyInfo, DigestAlgorithm, EC2Curve, ValidityInfo, EC2Y,
    },
    issuance::{Mdoc, X5Chain},
};
use p256::{
    ecdsa::{Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
};
use sec1::DecodeEcPrivateKey;
use serde_json::json;
use time::OffsetDateTime;

pub(crate) fn generate_credential() -> Wallet {
    let key = p256::SecretKey::random(&mut rand::thread_rng());
    let issuer = issuer();

    let doc_type = String::from("org.iso.18013.5.1.mDL");

    let isomdl_namespace = String::from("org.iso.18013.5.1");
    let isomdl_data = isomdl_data().to_ns_map();
    let namespaces = [(isomdl_namespace, isomdl_data)].into_iter().collect();

    let validity_info = ValidityInfo {
        signed: OffsetDateTime::now_utc(),
        valid_from: OffsetDateTime::now_utc(),
        valid_until: OffsetDateTime::now_utc() + Duration::from_secs(60),
        expected_update: None,
    };

    let digest_algorithm = DigestAlgorithm::SHA256;

    let pub_key = key.public_key();
    let ec = pub_key.to_encoded_point(false);
    let x = ec.x().unwrap().to_vec();
    let y = EC2Y::Value(ec.y().unwrap().to_vec());
    let device_key = CoseKey::EC2 {
        crv: EC2Curve::P256,
        x,
        y,
    };
    let device_key_info = DeviceKeyInfo {
        device_key,
        key_authorizations: None,
        key_info: None,
    };

    let mdl = Mdoc::builder()
        .doc_type(doc_type)
        .namespaces(namespaces)
        .validity_info(validity_info)
        .digest_algorithm(digest_algorithm)
        .device_key_info(device_key_info)
        .issue::<SigningKey, Signature>(issuer.x5chain, issuer.signer)
        .unwrap()
        .into();

    Wallet { key, mdl }
}

struct Issuer {
    x5chain: X5Chain,
    signer: SigningKey,
}

fn issuer() -> Issuer {
    let signer_pem = include_str!("../test/signer-key.pem");
    let signer = SigningKey::from_sec1_pem(signer_pem).unwrap();

    let signer_cert_pem = include_bytes!("../test/signer-cert.pem");
    let x5chain = X5Chain::builder()
        .with_pem(signer_cert_pem)
        .unwrap()
        .build()
        .unwrap();

    Issuer { x5chain, signer }
}

fn isomdl_data() -> OrgIso1801351 {
    let isomdl_json = json!(
        {
            "family_name":"Smith",
            "given_name":"Alice",
            "birth_date":"1980-01-01",
            "issue_date":"2020-01-01",
            "expiry_date":"2030-01-01",
            "issuing_country":"US",
            "issuing_authority":"NY DMV",
            "document_number":"DL12345678",
            "portrait":include_str!("../test/portrait.b64"),
            "driving_privileges":[
              {
                 "vehicle_category_code":"A",
                 "issue_date":"2020-01-01",
                 "expiry_date":"2030-01-01"
              },
              {
                 "vehicle_category_code":"B",
                 "issue_date":"2020-01-01",
                 "expiry_date":"2030-01-01"
              }
            ],
            "un_distinguishing_sign":"USA",
            "administrative_number":"ABC123",
            "sex":1,
            "height":170,
            "weight":70,
            "eye_colour":"hazel",
            "hair_colour":"red",
            "birth_place":"Canada",
            "resident_address":"138 Eagle Street",
            "portrait_capture_date":"2020-01-01T12:00:00Z",
            "age_in_years":43,
            "age_birth_year":1980,
            "age_over_18":true,
            "age_over_21":true,
            "issuing_jurisdiction":"US-NY",
            "nationality":"US",
            "resident_city":"Albany",
            "resident_state":"New York",
            "resident_postal_code":"12202-1719",
            "resident_country": "US"
        }
    );
    OrgIso1801351::from_json(&isomdl_json).unwrap()
}
