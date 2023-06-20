use curve25519_dalek_ng::scalar::Scalar;

///Util functions

pub fn hadamard_V(a: &Vec<Scalar>, b: &Vec<Scalar>) -> Vec<Scalar> {
    let a_len = a.len();

    if a_len != b.len() {
        panic!("hadamard_V(a, b): a and b should have same size");
    }

    let mut out: Vec<Scalar> = (0..a.len()).map(|_| Scalar::one()).collect();

    for i in 0..a_len {
        out[i] *= a[i] * b[i];
    }

    out
}

pub fn vm_mult(a: &Vec<Scalar>, b: &Vec<Vec<Scalar>>) -> Vec<Scalar> {
    let a_len = a.len();
    let b_len = b[0].len();

    if a_len != b_len {
        panic!("vm_mult(a,b): a -> 1xm, b -> mxn needs to be");
    }

    let mut out: Vec<Scalar> = (0..a_len).map(|_| Scalar::zero()).collect();
    
    for i in 0..a_len {
        let col: Vec<Scalar> = (0..a_len).map(|j| b[i][j]).collect();
        out[i] += inner_product(&a, &col);
    }

    out
}

pub fn mv_mult(a: &Vec<Vec<Scalar>>, b: &Vec<Scalar>) -> Vec<Scalar> {
    let b_len = b.len();
    let a_len = a.len();

    if a_len != b_len {
        panic!("mv_mult(a,b): a->nxm, b->mx1 needs to be");
    }

    let mut out: Vec<Scalar> = vec![Scalar::zero(); a[0].len()];

    for i in 0..a[0].len() {
        out[i] = inner_product(&(a[i]), b);
    }

    out
}

pub fn lm_mult(a: &[Scalar], b: &Vec<Vec<Scalar>>) -> Vec<Scalar> {
    let m = Vec::from(a);
    vm_mult(&m, b)
}

pub fn exp_iter(x:Scalar) -> ScalarExp {
    let next_exp_x = Scalar::one();
    ScalarExp { x, next_exp_x }
}

pub fn scalar_exp_u(x: &Scalar, pow: usize) -> Scalar {
    let mut result = Scalar::one();
    for i in 0..pow {
        result *= x;
    }

    result
}
pub fn scalar_exp(x: &Scalar, pow: i32) -> Scalar {
    let mut result = Scalar::one();
    for i in 0..pow {
        result *= x;
    }

    result
}

pub fn inner_product(a: &Vec<Scalar>, b: &Vec<Scalar>) -> Scalar {
    let mut out = Scalar::zero();
    if a.len() != b.len() {
        panic!("inner_product(a,b): lengths dont match");
    }
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out

}

/// Iterator for Scalar exponentiation
pub struct ScalarExp {
    x: Scalar,
    next_exp_x: Scalar,
}

impl Iterator for ScalarExp {
    type Item = Scalar;

    fn next(&mut self) -> Option<Scalar> {
        let exp_x = self.next_exp_x;
        self.next_exp_x *= self.x;
        Some(exp_x)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::max_value(), None)
    }
}
