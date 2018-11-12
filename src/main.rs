extern crate clap;
extern crate hyper;
extern crate hyper_tls;
extern crate mach_object;
extern crate plist;
extern crate regex;
extern crate regex_syntax;
extern crate serde;
extern crate serde_json;
extern crate termcolor;
extern crate tokio;
extern crate zip;

#[macro_use]
extern crate serde_derive;

use self::ios::aasa;
use self::ios::check;
use self::ios::entitlements;
use self::ios::report;
use clap::{App, Arg, SubCommand};
use crate::ios::aasa::get_aasa_to_report;
use crate::ios::report::report_aasa_human;
use crate::ios::report::report_entitlements_human;
use futures::Future;
use http::Uri;
use std::env;
use std::fs;
use std::process;

fn main() {
    let matches = App::new("Universal Link Validator")
        .version("0.1")
        .author("Daniel Basedow")
        /*
        .arg(
            Arg::with_name("ios-executable")
                .long("ios-executable")
                .value_name("FILE")
                .help("iOS executable to check against")
                .takes_value(true),
        )
        */
        .arg(
            Arg::with_name("bundle-identifier")
                .long("bundle-id")
                .value_name("ID")
                .help("Bundle identifier to match against")
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

    if let Some(ipa) = matches.value_of("ipa") {
        fs::metadata(ipa).expect("IPA file not found");
    }

    if url.host().is_none() {
        panic!("URL must contain a host");
    }

    let mut bundle_identifier = matches.value_of("bundle-identifier");

    println!("Running checks for link: {}", url);

    let p_ipa = check::IPACheck::from_cli_args(&matches);

    let candidate_a = aasa::well_known_aasa_from_url(&url);
    let p_aasa_1 = aasa::fetch_and_check(candidate_a, url.path());

    let candidate_b = aasa::root_aasa_from_url(&url);
    let p_aasa_2 = aasa::fetch_and_check(candidate_b, url.path());

    let p = p_ipa
        .join3(p_aasa_1, p_aasa_2)
        .and_then(|(ios_check, aasa_check_1, aasa_check_2)| {
            report_entitlements_human(ios_check);
            let aasa_check = get_aasa_to_report(&aasa_check_1, &aasa_check_2);

            report_aasa_human(&aasa_check);
            Ok(())
        });

    tokio::run(p);
}

mod ios;
