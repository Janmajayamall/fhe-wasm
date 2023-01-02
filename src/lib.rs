use fhe::bfv::{BfvParameters, BfvParametersBuilder, GaloisKey, SecretKey};
use fhe_math::rns::{RnsContext, RnsScaler, ScalingFactor};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::{thread_rng, RngCore};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn gen

#[wasm_bindgen]
pub fn test_scalar_32() {
    // let mut rng = thread_rng();
    // let par = BfvParameters::default_parameters_128(11)[0].clone();
    // let sk = SecretKey::random(&par, &mut rng);
    // let g = GaloisKey::new(&sk, 3, 0, 0, &mut rng);

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
