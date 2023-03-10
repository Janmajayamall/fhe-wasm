use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Encoding, EvaluationKeyBuilder, GaloisKey, Plaintext,
    SecretKey,
};
use fhe_math::rns::{RnsContext, RnsScaler, ScalingFactor};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
};
use fhe_util::sample_vec_cbd;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use omr::{
    client::{construct_lhs, construct_rhs, gen_pvw_sk_cts, pv_decompress},
    pvw::{PvwCiphertext, PvwParameters, PvwPublicKey, PvwSecretKey},
    utils::{
        assign_buckets, deserialize_detection_key, deserialize_digest1, deserialize_digest2,
        gen_detection_key, gen_rlk_keys_levelled, gen_rot_keys_inner_product,
        gen_rot_keys_pv_selector, gen_srlc_params, serialize_detection_key, solve_equations,
    },
    DEGREE, GAMMA, K, M, MODULI_OMR, MODULI_OMR_PT, M_ROW_SPAN, SET_SIZE, VARIANCE,
};
use rand::{distributions::Uniform, thread_rng, CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use std::{collections::HashMap, fmt::format, io::Write, sync::Arc};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));
}

fn get_bfv_params() -> Arc<BfvParameters> {
    // instantiate bfv params
    Arc::new(
        BfvParametersBuilder::new()
            .set_degree(DEGREE)
            .set_moduli(MODULI_OMR)
            .set_plaintext_modulus(MODULI_OMR_PT[0])
            .set_variance(VARIANCE)
            .build()
            .unwrap(),
    )
}

fn get_pvw_params() -> Arc<PvwParameters> {
    Arc::new(PvwParameters::default())
}

#[wasm_bindgen]
pub fn generate_bfv_secret() -> Vec<u8> {
    let mut rng = thread_rng();
    let sk = sample_vec_cbd(DEGREE, VARIANCE, &mut rng).unwrap();
    bincode::serialize(&sk).unwrap()
}

#[wasm_bindgen]
pub fn generate_pvw_secret() -> Vec<u8> {
    let mut rng = thread_rng();
    let par = get_pvw_params();
    let sk = PvwSecretKey::random(&par, &mut rng);
    sk.to_bytes()
}

#[wasm_bindgen]
pub fn generate_pvw_public_key(serialised_sk: &[u8]) -> Vec<u8> {
    let mut rng = thread_rng();
    let par = get_pvw_params();
    let sk = PvwSecretKey::from_bytes(serialised_sk, &par);
    let pk = sk.public_key(&mut rng);
    pk.to_bytes()
}

#[wasm_bindgen]
pub fn gen_clue(serialised_pk: &[u8]) -> Vec<u8> {
    let mut rng = thread_rng();
    let par = get_pvw_params();
    let pk = PvwPublicKey::from_bytes(serialised_pk, &par);
    let ct = pk.encrypt(vec![0; par.ell].as_slice(), &mut rng);
    ct.to_bytes()
}

#[wasm_bindgen]
pub fn generate_detection_key_pvw_sk_cts(bfv_sk: Vec<u8>, pvw_sk_bytes: &[u8]) -> Vec<u8> {
    let mut rng = thread_rng();

    let bfv_par = get_bfv_params();
    let bfv_sk: Vec<i64> = bincode::deserialize(&bfv_sk).unwrap();
    let bfv_sk = SecretKey::new(bfv_sk, &bfv_par);

    let pvw_par = get_pvw_params();
    let pvw_sk = PvwSecretKey::from_bytes(pvw_sk_bytes, &pvw_par);

    let cts = gen_pvw_sk_cts(&bfv_par, &pvw_par, &bfv_sk, &pvw_sk, &mut rng);

    let mut serialised_dkey = vec![];

    cts.iter()
        .for_each(|c| serialised_dkey.extend_from_slice(&c.to_bytes()));

    serialised_dkey
}

#[wasm_bindgen]
pub fn generate_detection_key_eks(bfv_sk: Vec<u8>) -> Vec<u8> {
    let mut rng = thread_rng();

    let bfv_par = get_bfv_params();
    let bfv_sk: Vec<i64> = bincode::deserialize(&bfv_sk).unwrap();
    let bfv_sk = SecretKey::new(bfv_sk, &bfv_par);

    let ek1 = EvaluationKeyBuilder::new_leveled(&bfv_sk, 0, 0)
        .unwrap()
        .enable_column_rotation(1)
        .unwrap()
        .build(&mut rng)
        .unwrap();
    let ek2 = gen_rot_keys_pv_selector(&bfv_par, &bfv_sk, 11, 10, &mut rng);
    let ek3 = gen_rot_keys_inner_product(&bfv_par, &bfv_sk, 13, 12, &mut rng);

    let mut serialised = vec![];
    serialised.extend_from_slice(ek1.to_bytes().as_slice());
    serialised.extend_from_slice(ek2.to_bytes().as_slice());
    serialised.extend_from_slice(ek3.to_bytes().as_slice());

    serialised
}

#[wasm_bindgen]
pub fn generate_detection_key_rlks(bfv_sk: Vec<u8>) -> Vec<u8> {
    let mut rng = thread_rng();

    let bfv_par = get_bfv_params();
    let bfv_sk: Vec<i64> = bincode::deserialize(&bfv_sk).unwrap();
    let bfv_sk = SecretKey::new(bfv_sk, &bfv_par);

    let rlk_keys = gen_rlk_keys_levelled(&bfv_par, &bfv_sk, &mut rng);

    let mut serialised = vec![];
    (1..12).into_iter().for_each(|index| {
        serialised.extend_from_slice(
            rlk_keys
                .get(&index)
                .unwrap_or_else(|| panic!("Rlk key for {index} should be generated"))
                .to_bytes()
                .as_slice(),
        );
    });

    serialised
}

#[wasm_bindgen]
pub fn decrypt_digest1(sk: Vec<u8>, digest: Vec<u8>) -> Vec<usize> {
    let par = get_bfv_params();
    let sk: Vec<i64> = bincode::deserialize(&sk).unwrap();
    let sk = SecretKey::new(sk, &par);

    let digest = deserialize_digest1(&digest, &par);
    let pv: Vec<u64> = digest
        .cts
        .iter()
        .flat_map(|c| {
            let pt = sk.try_decrypt(&c).unwrap();
            Vec::<u64>::try_decode(&pt, Encoding::simd()).unwrap()
        })
        .collect();

    let mut indices = vec![];
    pv_decompress(&pv, 16)
        .iter()
        .enumerate()
        .for_each(|(index, v)| {
            if *v == 1 {
                indices.push(index);
            }
        });
    indices
}

#[wasm_bindgen]
pub fn decrypt_digest2(
    sk: Vec<u8>,
    indices: Vec<usize>,
    digest: Vec<u8>,
    max_txs: usize,
) -> Vec<u8> {
    let par = get_bfv_params();
    let sk: Vec<i64> = bincode::deserialize(&sk).unwrap();
    let sk = SecretKey::new(sk, &par);

    // deserialize digest
    let digest = deserialize_digest2(&digest, &par);

    // values for rhs
    let values = digest
        .cts
        .iter()
        .flat_map(|ct| {
            let pt = sk.try_decrypt(ct).unwrap();
            Vec::<u64>::try_decode(&pt, Encoding::simd()).unwrap()
        })
        .collect::<Vec<u64>>();

    // srlc params
    let max_txs = (max_txs as f64 / 64.0).ceil() as usize * 64;
    let (k, m, gamma) = gen_srlc_params(max_txs);
    let set_size = indices.iter().max().unwrap() + 1;

    // seed the rng
    let mut s: <ChaChaRng as SeedableRng>::Seed = Default::default();
    s.copy_from_slice(&digest.seed);
    let mut rng = ChaChaRng::from_seed(s);
    let (assigned_buckets, assigned_weights) =
        assign_buckets(m, gamma, MODULI_OMR_PT[0], set_size, &mut rng);

    let mut lhs = vec![vec![0u64; k]; m];
    for i in 0..indices.len() {
        let index = indices[i];
        for j in 0..gamma {
            let bucket = assigned_buckets[index][j];
            let weight = assigned_weights[index][j];
            lhs[bucket][i] = weight;
        }
    }
    let rhs = construct_rhs(&values, m, 256, MODULI_OMR_PT[0]);
    let solutions = solve_equations(lhs, rhs, MODULI_OMR_PT[0]);

    solutions
        .iter()
        .flat_map(|sol| {
            sol.iter().map(|v| {
                let v_hi = (v >> 8);
                let v_lo = v - (v << 8);
                [v_lo as u8, v_hi as u8]
            })
        })
        .flatten()
        .collect()
}

#[wasm_bindgen]
pub fn serialise_sk_rs(sk: Box<[i64]>) -> Vec<u8> {
    bincode::serialize(&sk).unwrap()
}

#[wasm_bindgen]
pub fn test_scalar_32() {
    // Testing Scalar for wasm32
    let n = BigUint::from(4611686018326724610u64);
    let d = BigUint::from(1000u64);

    let q_moduli = [4u64, 4611686018326724609, 1153];
    let q = Arc::new(RnsContext::new(&q_moduli).unwrap());
    let r = Arc::new(
        RnsContext::new(&[
            4u64,
            4611686018326724609,
            1153,
            4611686018309947393,
            4611686018282684417,
            4611686018257518593,
            4611686018232352769,
            4611686018171535361,
            4611686018106523649,
            4611686018058289153,
        ])
        .unwrap(),
    );

    let mut rng = thread_rng();
    let x = &[
        rng.next_u64() % q_moduli[0],
        rng.next_u64() % q_moduli[1],
        rng.next_u64() % q_moduli[2],
    ];

    let mut x_lift = q.lift(x.into());
    let mut x_sign = false;
    if x_lift >= q.modulus() >> 2 {
        x_sign = true;
        x_lift = q.modulus() - x_lift;
    }

    let scaler = RnsScaler::new(&q, &r, ScalingFactor::new(&n, &d));
    let res = scaler.scale_new((&x).into(), 10);

    let x_scaled_round = if x_sign {
        if d.to_u64().unwrap() % 2 == 0 {
            r.modulus() - ((x_lift * n + ((&d >> 1) - 1u64)) / &d) % r.modulus()
        } else {
            r.modulus() - ((x_lift * n + (&d >> 1)) / &d) % r.modulus()
        }
    } else {
        (x_lift * n + (&d >> 1)) / d
    };

    assert!(res == r.project(&x_scaled_round));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen_clue;
    use omr::pvw::{PvwParameters, PvwSecretKey};
    use rand::thread_rng;

    #[test]
    fn test_gen_clue() {
        let params = Arc::new(PvwParameters::default());
        let mut rng = thread_rng();
        let sk = PvwSecretKey::random(&params, &mut rng);
        let pk = sk.public_key(&mut rng);

        let pk_bytes = pk.to_bytes();
        let clue = gen_clue(&pk_bytes);
        let ct = PvwCiphertext::from_bytes(&clue, &params).unwrap();
        let pt = sk.decrypt_shifted(ct);
        assert_eq!(pt, vec![0, 0, 0, 0]);
    }
}
