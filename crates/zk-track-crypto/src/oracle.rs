use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Zero};

pub fn mod_reduce(value: &BigUint, modulus: &BigUint) -> BigUint {
    value % modulus
}

pub fn mod_add(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    (lhs + rhs) % modulus
}

pub fn mod_sub(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    if lhs >= rhs {
        (lhs - rhs) % modulus
    } else {
        (modulus - ((rhs - lhs) % modulus)) % modulus
    }
}

pub fn mod_mul(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    (lhs * rhs) % modulus
}

pub fn mod_pow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exponent, modulus)
}

pub fn mod_inverse(value: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = BigInt::from_biguint(Sign::Plus, modulus.clone());
    let mut new_r = BigInt::from_biguint(Sign::Plus, value % modulus);

    while !new_r.is_zero() {
        let quotient = &r / &new_r;

        let next_t = &t - (&quotient * &new_t);
        t = new_t;
        new_t = next_t;

        let next_r = &r - (&quotient * &new_r);
        r = new_r;
        new_r = next_r;
    }

    if r != BigInt::one() {
        return None;
    }

    if t.sign() == Sign::Minus {
        t += BigInt::from_biguint(Sign::Plus, modulus.clone());
    }

    t.to_biguint()
}

pub fn mod_pow_u64(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }

    let mut acc = 1u64;
    base %= modulus;
    while exponent > 0 {
        if exponent & 1 == 1 {
            acc = mul_mod_u64(acc, base, modulus);
        }
        base = mul_mod_u64(base, base, modulus);
        exponent >>= 1;
    }
    acc
}

pub fn add_mod_u64(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    ((lhs % modulus) + (rhs % modulus)) % modulus
}

pub fn sub_mod_u64(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    ((lhs % modulus) + modulus - (rhs % modulus)) % modulus
}

pub fn mul_mod_u64(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    let wide = (lhs as u128 * rhs as u128) % modulus as u128;
    wide as u64
}
