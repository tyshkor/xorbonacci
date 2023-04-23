use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
struct XorbonacciConfig {
    pub advice: [Column<Advice>; 4],
    pub s_add: Selector,
    pub s_xor: Selector,
    pub xor_table: [TableColumn; 3],
    pub idx_table: [TableColumn; 1],
    pub instance: Column<Instance>,
}

#[derive(Debug, Clone)]
struct XorbonacciChip<F: FieldExt> {
    config: XorbonacciConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> XorbonacciChip<F> {
    pub fn construct(config: XorbonacciConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> XorbonacciConfig {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let col_d = meta.advice_column();
        let s_add = meta.complex_selector();
        let s_xor = meta.complex_selector();
        let instance = meta.instance_column();

        let xor_table = [
            meta.lookup_table_column(),
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        ];

        let idx_table = [meta.lookup_table_column()];

        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        meta.enable_equality(col_d);
        meta.enable_equality(instance);

        meta.lookup(|meta| {
            let s = meta.query_selector(s_xor);
            let lhs = meta.query_advice(col_a, Rotation::cur());
            let rhs = meta.query_advice(col_b, Rotation::cur());
            let out = meta.query_advice(col_c, Rotation::cur());
            vec![
                (s.clone() * lhs, xor_table[0]),
                (s.clone() * rhs, xor_table[1]),
                (s * out, xor_table[2]),
            ]
        });

        meta.lookup(|meta| {
            let s = meta.query_selector(s_add);
            let lhs = meta.query_advice(col_c, Rotation::cur());
            let rhs = meta.query_advice(col_d, Rotation::cur());
            vec![(s * (rhs - lhs), idx_table[0])]
        });

        XorbonacciConfig {
            advice: [col_a, col_b, col_c, col_d],
            s_add,
            s_xor,
            xor_table,
            idx_table,
            instance,
        }
    }

    fn load_tables(&self, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "xor_table",
            |mut table| {
                let mut idx = 0;
                for lhs in 0..256 {
                    for rhs in 0..256 {
                        table.assign_cell(
                            || "lhs",
                            self.config.xor_table[0],
                            idx,
                            || Value::known(F::from(lhs)),
                        )?;
                        table.assign_cell(
                            || "rhs",
                            self.config.xor_table[1],
                            idx,
                            || Value::known(F::from(rhs)),
                        )?;
                        table.assign_cell(
                            || "lhs ^ rhs",
                            self.config.xor_table[2],
                            idx,
                            || Value::known(F::from(lhs ^ rhs)),
                        )?;
                        idx += 1;
                    }
                }
                Ok(())
            },
        )?;
        layouter.assign_table(
            || "idx_table",
            |mut table| {
                for idx in 0..256 {
                    table.assign_cell(
                        || "idx",
                        self.config.idx_table[0],
                        idx,
                        || Value::known(F::from(idx as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }

    #[allow(clippy::type_complexity)]
    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        nrows: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let first_nontrivial_n = 2;
        layouter.assign_region(
            || "entire circuit",
            |mut region| {
                // assign first row
                let a_cell = region.assign_advice_from_instance(
                    || "1",
                    self.config.instance,
                    0,
                    self.config.advice[0],
                    0,
                )?;
                let mut b_cell = region.assign_advice_from_instance(
                    || "1",
                    self.config.instance,
                    1,
                    self.config.advice[1],
                    0,
                )?;
                let c_cell = region.assign_advice(
                    || "advice",
                    self.config.advice[2],
                    0,
                    || {
                        b_cell.value().and_then(|a| {
                            a_cell.value().map(|b| {
                                let a_val = a.get_lower_32() as u64;
                                let b_val = b.get_lower_32() as u64;
                                F::from(a_val ^ b_val)
                            })
                        })
                    },
                )?;

                let mut d_cell = region.assign_advice(
                    || "1",
                    self.config.advice[3],
                    0,
                    || {
                        c_cell.value().map(|c| {
                            let c_val = c.get_lower_32() as u64;
                            F::from(c_val + first_nontrivial_n)
                        })
                    },
                )?;

                // assign the rest of rows
                for row in 1..nrows {
                    b_cell.copy_advice(|| "a", &mut region, self.config.advice[0], row)?;
                    d_cell.copy_advice(|| "b", &mut region, self.config.advice[1], row)?;

                    let new_c_cell = {
                        self.config.s_xor.enable(&mut region, row)?;
                        region.assign_advice(
                            || "advice",
                            self.config.advice[2],
                            row,
                            || {
                                b_cell.value().and_then(|b| {
                                    d_cell.value().map(|d| {
                                        let b_val = b.get_lower_32() as u64;
                                        let d_val = d.get_lower_32() as u64;
                                        F::from(b_val ^ d_val)
                                    })
                                })
                            },
                        )?
                    };

                    let new_d_cell = {
                        self.config.s_add.enable(&mut region, row)?;
                        region.assign_advice(
                            || "advice",
                            self.config.advice[3],
                            row,
                            || {
                                new_c_cell.value().map(|new_c| {
                                    let new_c_val = new_c.get_lower_32() as u64;
                                    F::from(new_c_val + first_nontrivial_n + row as u64)
                                })
                            },
                        )?
                    };

                    b_cell = d_cell.clone();
                    d_cell = new_d_cell.clone();
                }

                Ok(d_cell)
            },
        )
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}

#[derive(Default)]
struct XorbonacciCircuit<F>(PhantomData<F>);

impl<F: FieldExt> Circuit<F> for XorbonacciCircuit<F> {
    type Config = XorbonacciConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        XorbonacciChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = XorbonacciChip::construct(config);
        chip.load_tables(layouter.namespace(|| "lookup table"))?;
        let out_cell = chip.assign(layouter.namespace(|| "entire table"), 11)?;
        chip.expose_public(layouter.namespace(|| "out"), out_cell, 2)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::XorbonacciCircuit;
    use halo2_proofs::{dev::MockProver, pasta::Fp};
    use std::marker::PhantomData;

    #[test]
    fn test_f_12() {
        let k = 17;

        let a = Fp::from(1); // F[0]
        let b = Fp::from(1); // F[1]
        let out = Fp::from(65); // F[12]

        let circuit = XorbonacciCircuit(PhantomData);

        let public_input = vec![a, b, out];

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }
}
