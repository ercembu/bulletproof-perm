use curve25519_dalek_ng::scalar::Scalar;
use crate::util::{*};

///Structs
pub struct Poly6 {
    pub t1: Scalar,
    pub t2: Scalar,
    pub t3: Scalar,
    pub t4: Scalar,
    pub t5: Scalar,
    pub t6: Scalar,
}

impl Poly6 {
    pub fn eval(&self, x: Scalar) -> Scalar {
        x * (self.t1 + x * (self.t2 + x * (self.t3 + x * (self.t4 + x * (self.t5 + x * self.t6)))))
    }
}


pub struct VecPoly3(
    pub Vec<Scalar>,
    pub Vec<Scalar>,
    pub Vec<Scalar>,
    pub Vec<Scalar>,
);

impl VecPoly3 {
    pub fn zero(n: usize) -> Self {
        VecPoly3(
            vec![Scalar::zero(); n],
            vec![Scalar::zero(); n],
            vec![Scalar::zero(); n],
            vec![Scalar::zero(); n],
        )
    }

    pub fn special_inner_product(lhs: &Self, rhs: &Self) -> Poly6 {
        let t1 = inner_product(&lhs.1, &rhs.0);
        let t2 = inner_product(&lhs.1, &rhs.1) + inner_product(&lhs.2, &rhs.0);
        let t3 = inner_product(&lhs.2, &rhs.1) + inner_product(&lhs.3, &rhs.0);
        let t4 = inner_product(&lhs.1, &rhs.3) + inner_product(&lhs.3, &rhs.1);
        let t5 = inner_product(&lhs.2, &rhs.3);
        let t6 = inner_product(&lhs.3, &rhs.3);

        Poly6 {
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
        }
    }

    pub fn eval(&self, x: Scalar) -> Vec<Scalar> {
        let n = self.0.len();
        let mut out = vec![Scalar::zero(); n];
        
        let out = self.0[i] + x * (self.1[i] + x * (self.2[i] + x * self.3[i]));
        out
    }
}
