use std::borrow::Cow;

/// BN254 Fr element: 32 bytes big-endian.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bn254Fr(pub [u8; 32]);

/// BN254 G1 affine uncompressed: X || Y, each 32 bytes big-endian.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bn254G1(pub [u8; 64]);

/// BN254 G2 affine uncompressed: X.A1 || X.A0 || Y.A1 || Y.A0, each 32 bytes big-endian.
/// A1 (imaginary part) precedes A0 (real part) — gnark WriteRawTo convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bn254G2(pub [u8; 128]);

/// Canonical inner proof — the contract between a Rust plugin and the outer prover.
///
/// `system_id` uses `Cow<'static, str>` so that plugin code can pass `&'static str` literals
/// (e.g. `"risc0-v3"`) with zero allocation, while deserialization can produce `Cow::Owned`
/// from a parsed string. The alternative — keeping `&'static str` — would require either
/// leaking memory or a compile-time registry of every known system ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalInnerProof {
    pub vk: Bn254Vk,
    pub proof: Bn254Proof,
    /// Real inputs only, length == n_real. No padding.
    pub public_inputs: Vec<Bn254Fr>,
    pub system_id: Cow<'static, str>,
}

impl CanonicalInnerProof {
    pub fn vk_bytes(&self) -> Vec<u8> {
        self.vk.to_bytes()
    }

    pub fn proof_bytes(&self) -> [u8; 256] {
        self.proof.to_bytes()
    }

    pub fn public_inputs_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.public_inputs.len() * 32);
        for fr in &self.public_inputs {
            buf.extend_from_slice(&fr.0);
        }
        buf
    }

    pub fn meta_json(&self) -> String {
        format!(
            r#"{{"system_id":"{}","n_real":{}}}"#,
            self.system_id,
            self.public_inputs.len()
        )
    }

    pub fn from_parts(
        vk_bytes: &[u8],
        proof_bytes: &[u8; 256],
        pi_bytes: &[u8],
        meta_json: &str,
    ) -> Result<Self, ParseError> {
        let vk = Bn254Vk::from_bytes(vk_bytes)?;
        let proof = Bn254Proof::from_bytes(proof_bytes);
        let (system_id, n_real) = parse_meta_json(meta_json)?;
        if pi_bytes.len() != n_real * 32 {
            return Err(ParseError::PublicInputsLen);
        }
        if vk.ic.len() != n_real + 1 {
            return Err(ParseError::IcLenMismatch);
        }
        let mut public_inputs = Vec::with_capacity(n_real);
        for i in 0..n_real {
            let s = i * 32;
            public_inputs.push(Bn254Fr(pi_bytes[s..s + 32].try_into().unwrap()));
        }
        Ok(CanonicalInnerProof {
            vk,
            proof,
            public_inputs,
            system_id: Cow::Owned(system_id),
        })
    }
}

fn parse_meta_json(s: &str) -> Result<(String, usize), ParseError> {
    let system_id = extract_json_string(s, "system_id")?;
    let n_real = extract_json_uint(s, "n_real")?;
    Ok((system_id, n_real))
}

fn extract_json_string(json: &str, key: &str) -> Result<String, ParseError> {
    let needle = format!(r#""{key}":""#);
    let start = json.find(&needle).ok_or(ParseError::InvalidMeta)? + needle.len();
    let end = json[start..].find('"').ok_or(ParseError::InvalidMeta)? + start;
    Ok(json[start..end].to_owned())
}

fn extract_json_uint(json: &str, key: &str) -> Result<usize, ParseError> {
    let needle = format!(r#""{key}":"#);
    let start = json.find(&needle).ok_or(ParseError::InvalidMeta)? + needle.len();
    let tail = &json[start..];
    let end = tail
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(tail.len());
    tail[..end]
        .parse::<usize>()
        .map_err(|_| ParseError::InvalidMeta)
}

/// Error type for canonical proof deserialization.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    PublicInputsLen,
    IcLenMismatch,
    InvalidMeta,
}

/// BN254 Groth16 verifying key. vk.bin layout: alpha_g1[0:64] | beta_g2[64:192] |
/// gamma_g2[192:320] | delta_g2[320:448] | n_ic u32-BE[448:452] | IC[452..].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bn254Vk {
    pub alpha_g1: Bn254G1,
    pub beta_g2: Bn254G2,
    pub gamma_g2: Bn254G2,
    pub delta_g2: Bn254G2,
    /// IC[0] is the constant term; IC[1..] are per-input. len() == n_real + 1.
    pub ic: Vec<Bn254G1>,
}

impl Bn254Vk {
    pub fn to_bytes(&self) -> Vec<u8> {
        let n_ic = self.ic.len() as u32;
        let mut buf = Vec::with_capacity(452 + self.ic.len() * 64);
        buf.extend_from_slice(&self.alpha_g1.0);
        buf.extend_from_slice(&self.beta_g2.0);
        buf.extend_from_slice(&self.gamma_g2.0);
        buf.extend_from_slice(&self.delta_g2.0);
        buf.extend_from_slice(&n_ic.to_be_bytes());
        for pt in &self.ic {
            buf.extend_from_slice(&pt.0);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 452 {
            return Err(ParseError::TooShort);
        }
        let alpha_g1 = Bn254G1(data[0..64].try_into().unwrap());
        let beta_g2 = Bn254G2(data[64..192].try_into().unwrap());
        let gamma_g2 = Bn254G2(data[192..320].try_into().unwrap());
        let delta_g2 = Bn254G2(data[320..448].try_into().unwrap());
        let n_ic = u32::from_be_bytes(data[448..452].try_into().unwrap()) as usize;
        if data.len() < 452 + n_ic * 64 {
            return Err(ParseError::TooShort);
        }
        let mut ic = Vec::with_capacity(n_ic);
        for i in 0..n_ic {
            let s = 452 + i * 64;
            ic.push(Bn254G1(data[s..s + 64].try_into().unwrap()));
        }
        Ok(Bn254Vk {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        })
    }
}

/// BN254 Groth16 proof. proof.bin layout: ar[0:64] | bs[64:192] | krs[192:256].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bn254Proof {
    pub ar: Bn254G1,
    pub bs: Bn254G2,
    pub krs: Bn254G1,
}

impl Bn254Proof {
    pub fn to_bytes(&self) -> [u8; 256] {
        let mut buf = [0u8; 256];
        buf[0..64].copy_from_slice(&self.ar.0);
        buf[64..192].copy_from_slice(&self.bs.0);
        buf[192..256].copy_from_slice(&self.krs.0);
        buf
    }

    pub fn from_bytes(data: &[u8; 256]) -> Self {
        Bn254Proof {
            ar: Bn254G1(data[0..64].try_into().unwrap()),
            bs: Bn254G2(data[64..192].try_into().unwrap()),
            krs: Bn254G1(data[192..256].try_into().unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_proof(n_real: usize) -> CanonicalInnerProof {
        let vk = Bn254Vk {
            alpha_g1: Bn254G1([0xAAu8; 64]),
            beta_g2: Bn254G2([0xBBu8; 128]),
            gamma_g2: Bn254G2([0xCCu8; 128]),
            delta_g2: Bn254G2([0xDDu8; 128]),
            ic: (0..=n_real).map(|i| Bn254G1([i as u8; 64])).collect(),
        };
        let proof = Bn254Proof {
            ar: Bn254G1([0x11u8; 64]),
            bs: Bn254G2([0x22u8; 128]),
            krs: Bn254G1([0x33u8; 64]),
        };
        let public_inputs = (0..n_real).map(|i| Bn254Fr([i as u8; 32])).collect();
        CanonicalInnerProof {
            vk,
            proof,
            public_inputs,
            system_id: std::borrow::Cow::Borrowed("risc0-v3"),
        }
    }

    #[test]
    fn from_parts_rejects_ic_mismatch() {
        let p = make_test_proof(2); // vk has 3 IC points (ic[0..=2]), n_real=2
                                    // Give the vk an extra IC point so n_ic=4 but meta still says n_real=2 → mismatch
        let mut bad_vk = p.vk.clone();
        bad_vk.ic.push(Bn254G1([0xFFu8; 64]));
        let vk_bytes = bad_vk.to_bytes();
        let proof_bytes = p.proof_bytes();
        let pi_bytes = p.public_inputs_bytes();
        let meta = p.meta_json(); // n_real=2, but vk.ic.len()==4 ≠ 3
        let result = CanonicalInnerProof::from_parts(&vk_bytes, &proof_bytes, &pi_bytes, &meta);
        assert_eq!(result, Err(ParseError::IcLenMismatch));
    }

    #[test]
    fn round_trip() {
        let original = make_test_proof(2);
        let vk_bytes = original.vk_bytes();
        let proof_bytes = original.proof_bytes();
        let pi_bytes = original.public_inputs_bytes();
        let meta = original.meta_json();

        let recovered =
            CanonicalInnerProof::from_parts(&vk_bytes, &proof_bytes, &pi_bytes, &meta).unwrap();

        assert_eq!(recovered.vk, original.vk);
        assert_eq!(recovered.proof, original.proof);
        assert_eq!(recovered.public_inputs, original.public_inputs);
        assert_eq!(recovered.system_id.as_ref(), original.system_id.as_ref());
    }

    #[test]
    fn meta_json_format() {
        let p = make_test_proof(2);
        assert_eq!(p.meta_json(), r#"{"system_id":"risc0-v3","n_real":2}"#);
    }

    #[test]
    fn vk_bytes_layout() {
        let alpha = Bn254G1([0x11u8; 64]);
        let beta = Bn254G2([0x22u8; 128]);
        let gamma = Bn254G2([0x33u8; 128]);
        let delta = Bn254G2([0x44u8; 128]);
        let ic0 = Bn254G1([0x55u8; 64]);
        let ic1 = Bn254G1([0x66u8; 64]);
        let vk = Bn254Vk {
            alpha_g1: alpha.clone(),
            beta_g2: beta.clone(),
            gamma_g2: gamma.clone(),
            delta_g2: delta.clone(),
            ic: vec![ic0.clone(), ic1.clone()],
        };
        let enc = vk.to_bytes();
        // 452-byte fixed header + 2 × 64-byte IC points
        assert_eq!(enc.len(), 452 + 2 * 64);
        assert_eq!(&enc[0..64], &alpha.0[..]);
        assert_eq!(&enc[64..192], &beta.0[..]);
        assert_eq!(&enc[192..320], &gamma.0[..]);
        assert_eq!(&enc[320..448], &delta.0[..]);
        assert_eq!(&enc[448..452], &2u32.to_be_bytes());
        assert_eq!(&enc[452..516], &ic0.0[..]);
        assert_eq!(&enc[516..580], &ic1.0[..]);
    }

    #[test]
    fn proof_bytes_layout() {
        let ar_bytes = [0x11u8; 64];
        let bs_bytes = [0x22u8; 128];
        let krs_bytes = [0x33u8; 64];
        let proof = Bn254Proof {
            ar: Bn254G1(ar_bytes),
            bs: Bn254G2(bs_bytes),
            krs: Bn254G1(krs_bytes),
        };
        let enc = proof.to_bytes();
        assert_eq!(enc.len(), 256);
        assert_eq!(&enc[0..64], &ar_bytes[..]);
        assert_eq!(&enc[64..192], &bs_bytes[..]);
        assert_eq!(&enc[192..256], &krs_bytes[..]);
    }
}
