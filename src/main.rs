extern crate hyper;
extern crate hyper_tls;
extern crate regex;
extern crate regex_syntax;
extern crate serde;
extern crate serde_json;
extern crate tokio;

#[macro_use]
extern crate serde_derive;

use http::Uri;
use hyper::rt::{self, Future};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let url: Uri = args.last().unwrap().parse().expect("invalid url");
    if url.host().is_none() {
        panic!("URL must contain a host");
    }

    println!("running check for {}", url);

    let candidate_a = aasa::well_known_aasa_from_url(&url);
    println!(
        "trying to fetch Apple app site association file {}",
        candidate_a
    );

    let p = aasa::fetch_and_check(candidate_a, url.path()).and_then(|matches| {
        for m in matches {
            println!("{}", m);
        }
        Ok(())
    });

    rt::run(p);
}

mod aasa;
