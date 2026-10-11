//! PUBLIC TEST FIXTURES ONLY. No production keys, entropy or HIBE interface.
//! Reuses unmodified MPL-2.0 qFALL functions through their public API.

use qfall_math::{integer::{MatZ, Z}, integer_mod_q::MatZq, traits::*};
use qfall_tools::sample::g_trapdoor::{
    gadget_classical::gen_gadget_mat, gadget_parameters::GadgetParameters,
    short_basis_classical::gen_short_basis_for_trapdoor,
};
use serde::Deserialize;
use serde_json::json;
use std::{io::{self, Read}, str::FromStr};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    public_test_fixture: bool,
    n: i64,
    q: i64,
    m_bar: i64,
    a_bar: Vec<Vec<i64>>,
    r: Vec<Vec<i64>>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().take(1_048_577).read_to_string(&mut input)?;
    if input.len() > 1_048_576 { return Err("fixture byte budget exceeded".into()); }
    let f: Fixture = serde_json::from_str(&input)?;
    if !f.public_test_fixture || !(1..=4).contains(&f.n)
        || !(2..=1_099_511_627_776).contains(&f.q) || !(1..=96).contains(&f.m_bar) {
        return Err("only bounded public teaching fixtures are accepted".into());
    }
    let mut gp = GadgetParameters::init_default(f.n, f.q);
    gp.m_bar = Z::from(f.m_bar);
    let k: i64 = (&gp.k).try_into()?;
    let cols = f.n * k;
    if f.m_bar + cols > 192
        || f.a_bar.len() != f.n as usize
        || f.a_bar.iter().any(|row| row.len() != f.m_bar as usize || row.iter().any(|x| *x < 0 || *x >= f.q))
        || f.r.len() != f.m_bar as usize
        || f.r.iter().any(|row| row.len() != cols as usize || row.iter().any(|x| !(-1..=1).contains(x))) {
        return Err("invalid or excessive fixture dimensions/residues".into());
    }
    let ab = MatZ::from_str(&serde_json::to_string(&f.a_bar)?)?;
    let r = MatZ::from_str(&serde_json::to_string(&f.r)?)?;
    let abq = MatZq::from((&ab, &gp.q));
    let g = gen_gadget_mat(f.n, &gp.k, &gp.base);
    let right = MatZq::from((&g, &gp.q)) - &abq * &r;
    let a = abq.concat_horizontal(&right)?;
    let tag = MatZq::identity(f.n, f.n, &gp.q);
    let basis = gen_short_basis_for_trapdoor(&gp, &tag, &a, &r);
    let ai = a.get_representative_least_nonnegative_residue();
    let rows = |m: &MatZ| -> Vec<Vec<String>> {
        (0..m.get_num_rows()).map(|i| (0..m.get_num_columns())
            .map(|j| { let value: Z = m.get_entry(i,j).unwrap(); value.to_string() }).collect()).collect()
    };
    println!("{}", json!({"public_test_fixture":true,"n":f.n,"q":f.q,"k":k,
        "m_bar":f.m_bar,"a":rows(&ai),"basis":rows(&basis),
        "security_claim":"none","backend_admitted":false}));
    Ok(())
}
