extern crate clap;
extern crate hyper;
extern crate hyper_tls;
extern crate mach_object;
extern crate plist;
extern crate regex;
extern crate regex_syntax;
extern crate serde;
extern crate serde_json;
extern crate tokio;

#[macro_use]
extern crate serde_derive;

use self::ios::aasa;
use self::ios::entitlements;
use clap::{App, Arg, SubCommand};
use futures::Future;
use http::Uri;
use std::env;
use std::process;

fn main() {
    let matches = App::new("Universal Link Validator")
        .version("0.1")
        .author("Daniel Basedow")
        .arg(
            Arg::with_name("ios-executable")
                .long("ios-executable")
                .value_name("FILE")
                .help("iOS executable to check against")
                .takes_value(true),
        )
        /*
        .arg(
            Arg::with_name("apk")
                .long("apk")
                .value_name("FILE")
                .help("APK to check against")
                .takes_value(true),
        )
        */
        .arg(
            Arg::with_name("ipa")
                .long("ipa")
                .value_name("FILE")
                .help("IPA to check against")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("URL")
                .value_name("URL")
                .help("URL to check against")
                .required(true)
                .index(1),
        )
        .get_matches();

    let url = matches.value_of("URL").unwrap();
    let url: Uri = url.parse().expect("invalid url");

    if url.host().is_none() {
        panic!("URL must contain a host");
    }

    println!("Running checks for link: {}", url);

    if let Some(fname) = matches.value_of("ios-executable") {
        if let Some(ents) = entitlements::extract_info_from_file(fname) {
            let domain = url.host().unwrap();
            if !ents.matches_applink_domain(domain) {
                println!("The entitlements in the supplied executable do not claim {} as an 'applinks' domain.", domain);
                println!("Found:");
                for d in ents.associated_domains {
                    println!("  {}", d);
                }
                println!("");
                println!("Missing:");
                println!("  applinks:{}", domain);
                process::exit(1);
            }
        }
    }

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

    tokio::run(p);
}

mod ios;
