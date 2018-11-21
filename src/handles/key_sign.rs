use openssl::hash;
use openssl::pkey;
use openssl::sign::Signer;

use base64;

pub fn sign(input: &[u8]) -> Result<Vec<u8>, ()> {
    let priv_key = generate_asn_pkey()?;
    let mut signer = generate_rsa_asn_signer(&priv_key)?;

    match signer.update(input) {
        Ok(_) => {}
        Err(e) => {
            error!("Sign data failed, {}", e);
            return Err(());
        }
    }

    match signer.sign_to_vec() {
        Ok(ret) => Ok(ret),
        Err(e) => {
            error!("Sign data to vec failed, {}", e);
            Err(())
        }
    }
}

#[allow(dead_code)]
pub fn sign8(input: &[u8]) -> Result<String, ()> {
    let priv_key = generate_pkcs8_pkey()?;
    let mut signer = generate_rsa_pkcs8_signer(&priv_key)?;

    match signer.update(input) {
        Ok(_) => {}
        Err(e) => {
            error!("Sign data failed, {}", e);
            return Err(());
        }
    }

    let sig = match signer.sign_to_vec() {
        Ok(s) => s,
        Err(e) => {
            error!("Sign data to vec failed, {}", e);
            return Err(());
        }
    };

    Ok(base64::encode(&sig))
}

static ASNKEY: &[u8] = b"
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALecq3BwAI4YJZwhJ+snnDFj3lF3DMqNPorV6y5ZKXCiCMqj8OeOmxk4YZW9aaV9
ckl/zlAOI0mpB3pDT+Xlj2sCAwEAAQJAW6/aVD05qbsZHMvZuS2Aa5FpNNj0BDlf38hOtkhDzz/h
kYb+EBYLLvldhgsD0OvRNy8yhz7EjaUqLCB0juIN4QIhAOeCQp+NXxfBmfdG/S+XbRUAdv8iHBl+
F6O2wr5fA2jzAiEAywlDfGIl6acnakPrmJE0IL8qvuO3FtsHBrpkUuOnXakCIQCqdr+XvADI/UTh
TuQepuErFayJMBSAsNe3NFsw0cUxAQIgGA5n7ZPfdBi3BdM4VeJWb87WrLlkVxPqeDSbcGrCyMkC
IFSs5JyXvFTreWt7IQjDssrKDRIPmALdNjvfETwlNJyY
-----END RSA PRIVATE KEY-----
";

static PKCS8KEY: &[u8] = b"
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAND3cI/pKMSd4OLMIXU/8xoEZ/nz
a+g00Vy7ygyGB1Nn83qpro7tckOvUVILJoN0pKw8J3E8rtjhSyr9849qzaQKBhxFL+J5uu08QVn/
tMt+Tf0cu5MSPOjT8I2+NWyBZ6H0FjOcVrEUMvHt8sqoJDrDU4pJyex2rCOlpfBeqK6XAgMBAAEC
gYBM5C+8FIxWxM1CRuCs1yop0aM82vBC0mSTXdo7/3lknGSAJz2/A+o+s50Vtlqmll4drkjJJw4j
acsR974OcLtXzQrZ0G1ohCM55lC3kehNEbgQdBpagOHbsFa4miKnlYys537Wp+Q61mhGM1weXzos
gCH/7e/FjJ5uS6DhQc0Y+QJBAP43hlSSEo1BbuanFfp55yK2Y503ti3Rgf1SbE+JbUvIIRsvB24x
Ha1/IZ+ttkAuIbOUomLN7fyyEYLWphIy9kUCQQDSbqmxZaJNRa1o4ozGRORxR2KBqVn3EVISXqNc
UH3gAP52U9LcnmA3NMSZs8tzXhUhYkWQ75Q6umXvvDm4XZ0rAkBoymyWGeyJy8oyS/fUW0G63mIr
oZZ4Rp+F098P3j9ueJ2k/frbImXwabJrhwjUZe/Afel+PxL2ElUDkQW+BMHdAkEAk/U7W4Aanjpf
s1+Xm9DUztFicciheRa0njXspvvxhY8tXAWUPYseG7L+iRPh+Twtn0t5nm7VynVFN0shSoCIAQJA
Ljo7A6bzsvfnJpV+lQiOqD/WCw3A2yPwe+1d0X/13fQkgzcbB3K0K81Euo/fkKKiBv0A7yR7wvrN
jzefE9sKUw==
-----END PRIVATE KEY-----
";

#[allow(dead_code)]
fn generate_asn_pkey() -> Result<pkey::PKey<pkey::Private>, ()> {
    // let rsa = generate_asn_rsa()?;
    // let keypair = pkey::PKey::private_key_from_pem(ASNKEY);
    let keypair = match pkey::PKey::private_key_from_pem(ASNKEY) {
        Ok(kp) => kp,
        Err(e) => {
            error!("PKey::from_rsa(ASNKEY) failed, {}", e);
            return Err(());
        }
    };

    Ok(keypair)
}

fn generate_rsa_asn_signer<'a>(priv_key: &'a pkey::PKey<pkey::Private>) -> Result<Signer<'a>, ()> {
    let signer = match Signer::new(hash::MessageDigest::md5(), &priv_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Signer with md5 from_rsa(ASNKEY) failed, {}", e);
            return Err(());
        }
    };

    Ok(signer)
}

fn generate_pkcs8_pkey() -> Result<pkey::PKey<pkey::Private>, ()> {
    let keypair = match pkey::PKey::private_key_from_pkcs8_passphrase(PKCS8KEY, b"") {
        Ok(kp) => kp,
        Err(e) => {
            error!("PKey::from_rsa(PKCS8KEY) failed, {}", e);
            return Err(());
        }
    };

    Ok(keypair)
}

fn generate_rsa_pkcs8_signer<'a>(
    priv_key: &'a pkey::PKey<pkey::Private>,
) -> Result<Signer<'a>, ()> {
    let signer = match Signer::new(hash::MessageDigest::sha1(), &priv_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Signer with sha1 from_rsa(PKCS8KEY) failed, {}", e);
            return Err(());
        }
    };

    Ok(signer)
}
