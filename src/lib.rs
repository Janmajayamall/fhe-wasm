use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, GaloisKey, SecretKey};
use fhe_math::rns::{RnsContext, RnsScaler, ScalingFactor};
use fhe_traits::{DeserializeParametrized, FheDecoder, FheDecrypter, FheEncrypter, Serialize};
use fhe_util::sample_vec_cbd;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use omr::{
    client::{construct_lhs, construct_rhs, pv_decompress},
    utils::{assign_buckets, solve_equations},
    GAMMA, K, M, MODULI_OMR_PT, M_ROW_SPAN, SET_SIZE,
};
use rand::{thread_rng, RngCore};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}
// Generate bindings for
// 1. New Secert key
// 2. Evaluation keys and Relinearisation keys
// 3. Fn that concats (2) and stores it for the user.
// 4. PVWWWW

const N: usize = 2048;
const VARIANCE: usize = 4;
const MODULI: [u64; 15] = [
    268369921,
    549755486209,
    1152921504606584833,
    1152921504598720513,
    1152921504597016577,
    1152921504595968001,
    1152921504595640321,
    1152921504593412097,
    1152921504592822273,
    1152921504592429057,
    1152921504589938689,
    1152921504586530817,
    4293918721,
    1073479681,
    1152921504585547777,
];
const T: u64 = 65537;
const CT_SPAN_COUNT: usize = 7;
const CT_BYTES: usize = 0;

fn get_params() -> Arc<BfvParameters> {
    // instantiate bfv params
    Arc::new(
        BfvParametersBuilder::new()
            .set_degree(N)
            .set_moduli(&MODULI)
            .set_plaintext_modulus(T)
            .set_variance(VARIANCE)
            .build()
            .unwrap(),
    )
}

#[wasm_bindgen]
pub fn generate_secret() -> Box<[i64]> {
    let mut rng = thread_rng();

    sample_vec_cbd(N, VARIANCE, &mut rng)
        .unwrap()
        .into_boxed_slice()
}

#[wasm_bindgen]
pub fn generate_detection_key(sk: Box<[i64]>) -> Box<[u8]> {
    let mut rng = thread_rng();

    // instantiate bfv params
    let par = Arc::new(
        BfvParametersBuilder::new()
            .set_degree(N)
            .set_moduli(&MODULI)
            .set_plaintext_modulus(T)
            .set_variance(VARIANCE)
            .build()
            .unwrap(),
    );
    let sk = SecretKey::new(sk.to_vec(), &par);

    // let g = GaloisKey::new(&sk, 3, 0, 0, &mut rng).unwrap();
    // let g = g.to_bytes();
    todo!()
}

#[wasm_bindgen]
pub fn decrypt_digest(sk: Box<[i64]>, digest: Vec<u8>) {
    // seed the rng
    let mut rng = thread_rng();

    let par = get_params();
    let sk = SecretKey::new(sk.to_vec(), &par);

    // digest -> ciphertexts
    let values = digest
        .chunks(CT_BYTES)
        .into_iter()
        .flat_map(|ct_bytes| {
            let ct = Ciphertext::from_bytes(ct_bytes, &par).unwrap();
            let pt = sk.try_decrypt(&ct).unwrap();
            Vec::<u64>::try_decode(&pt, Encoding::simd()).unwrap()
        })
        .collect::<Vec<u64>>();

    let pv = pv_decompress(
        &values[..par.degree()],
        (64 - (par.plaintext().leading_zeros() - 1)) as usize,
    );

    assign_buckets(M, GAMMA, MODULI_OMR_PT[0], SET_SIZE);

    let lhs = construct_lhs(
        &pv,
        assigned_buckets,
        assigned_weights,
        M,
        K,
        GAMMA,
        SET_SIZE,
    );
    let rhs = construct_rhs(&values[par.degree()..], M, M_ROW_SPAN, MODULI_OMR_PT[0]);
    let msgs = solve_equations(lhs, rhs, MODULI_OMR_PT[0]);
}

#[wasm_bindgen]
pub fn test_scalar_32() {
    // let mut rng = thread_rng();
    // let par = BfvParameters::default_parameters_128(11)[0].clone();
    // let sk = SecretKey::random(&par, &mut rng);

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

    if (res == r.project(&x_scaled_round)) {
        alert("Works!");
    } else {
        alert("Failed!");
    }
}
