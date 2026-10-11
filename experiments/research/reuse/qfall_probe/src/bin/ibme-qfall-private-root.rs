//! Secret-input MP12 full-basis engine. Entropy is supplied by the caller.
//! Separate versioned API; does not change or reuse the public-fixture flag.
//! No input/secret values are printed on errors; stdout is PRIVATE KEY DATA.

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
struct RootInput {
    schema: String,
    entropy_source: String,
    n: i64,
    q: i64,
    m_bar: i64,
    a_bar: Vec<Vec<i64>>,
    r: Vec<Vec<i64>>,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().take(33_554_433).read_to_string(&mut input)?;
    if input.len() > 33_554_432 { return Err("input budget".into()); }
    let f: RootInput = serde_json::from_str(&input)?;
    if f.schema != "IBME/MP12-SECRET-ROOT/1"
        || !["system", "external-byte-source", "deterministic-test"].contains(&f.entropy_source.as_str())
        || !(1..=64).contains(&f.n) || !(2..=2_305_843_009_213_693_951).contains(&f.q)
        || !(1..=2048).contains(&f.m_bar) { return Err("parameter domain".into()); }
    let mut gp = GadgetParameters::init_default(f.n, f.q);
    gp.m_bar = Z::from(f.m_bar);
    let k: i64 = (&gp.k).try_into()?;
    let cols = f.n * k;
    let dimension = f.m_bar + cols;
    if dimension > 1024 || f.m_bar * cols > 1_048_576
        || f.a_bar.len() != f.n as usize
        || f.a_bar.iter().any(|row| row.len() != f.m_bar as usize || row.iter().any(|x| *x < 0 || *x >= f.q))
        || f.r.len() != f.m_bar as usize
        || f.r.iter().any(|row| row.len() != cols as usize || row.iter().any(|x| !(-281_474_976_710_656..=281_474_976_710_656).contains(x))) {
        return Err("matrix domain".into());
    }
    let ab = MatZ::from_str(&serde_json::to_string(&f.a_bar)?)?;
    let r = MatZ::from_str(&serde_json::to_string(&f.r)?)?;
    let abq = MatZq::from((&ab, &gp.q));
    let g = gen_gadget_mat(f.n, &gp.k, &gp.base);
    let a = abq.concat_horizontal(&(MatZq::from((&g, &gp.q)) - &abq * &r))?;
    let tag = MatZq::identity(f.n, f.n, &gp.q);
    let basis = gen_short_basis_for_trapdoor(&gp, &tag, &a, &r);
    let ai = a.get_representative_least_nonnegative_residue();
    let rows = |m: &MatZ| -> Vec<Vec<String>> {
        (0..m.get_num_rows()).map(|i| (0..m.get_num_columns())
            .map(|j| { let z: Z = m.get_entry(i,j).unwrap(); z.to_string() }).collect()).collect()
    };
    println!("{}", json!({"schema":"IBME/MP12-SECRET-ROOT/1", "entropy_source":f.entropy_source,
        "n":f.n,"q":f.q,"k":k,"m_bar":f.m_bar,"a":rows(&ai),"basis":rows(&basis),
        "native_entropy_generated":false,"security_claim":"none","backend_admitted":false}));
    Ok(())
}

fn main() {
    if run().is_err() {
        eprintln!("private root engine rejected input or failed; secret diagnostics withheld");
        std::process::exit(2);
    }
}
