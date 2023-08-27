use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine};
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;

pub fn verify_jwt(token: &str, key: &str) -> Result<bool> {
    let raw_key = general_purpose::URL_SAFE_NO_PAD
        .decode(key.as_bytes())
        .context("key decoding")?;
    let mut ctx = BigNumContext::new().context("bignum context creation")?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).context("group creation")?;
    let p = EcPoint::from_bytes(&group, &raw_key, &mut ctx).context("loading key")?;

    let key = EcKey::from_public_key(&group, &p).context("key creation")?;

    key.check_key().context("key check")?;

    let pkey = openssl::pkey::PKey::from_ec_key(key).context("pkey creation")?;

    let (content, sig) = token.split_at(token.rfind('.').context("invalid format jwt")?);
    let sig = &sig[1..];

    let sig = general_purpose::URL_SAFE_NO_PAD
        .decode(sig)
        .context("signature decoding")?;

    anyhow::ensure!(sig.len() == 64, "invalid signature length");

    let mut sig_der = Vec::new();
    sig_der.extend(&[0x30, 0x00]);

    for i in 0..2 {
        sig_der.push(0x02); // integer
        if sig[i * 32] >= 0x80 {
            sig_der.extend(&[0x21, 0x00]);
        } else {
            sig_der.push(0x20);
        }
        sig_der.extend(&sig[i * 32..(i + 1) * 32]);
    }

    sig_der[1] = sig_der.len() as u8 - 2;

    let mut vfr = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &pkey)
        .context("verifier creation")?;
    vfr.verify_oneshot(&sig_der, content.as_bytes())
        .context("verification")
}
