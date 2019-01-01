extern crate clap;
extern crate mach_object;
extern crate plist;
extern crate regex;
extern crate regex_syntax;
extern crate serde;
extern crate serde_json;
extern crate zip;

#[macro_use]
extern crate serde_derive;

use self::ios::aasa;
use self::ios::report;
use crate::ios::aasa::fetch_and_check_sync;
use crate::ios::entitlements::extract_info_from_ipa;
use clap::{App, Arg, ArgMatches, SubCommand};
use http::Uri;
use std::fs;
use std::process;

fn main() {
    let matches = App::new("Universal Link Validator")
        .version("0.1")
        .author("Daniel Basedow")
        .subcommand(
            SubCommand::with_name("ios")
                .about("iOS related checks")
                .arg(
                    Arg::with_name("ipa")
                        .long("ipa")
                        .value_name("FILE")
                        .help("IPA to check against")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("bundle-identifier")
                        .value_name("BUNDLE_ID")
                        .help("Bundle Identifier of app")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("URL")
                        .value_name("URL")
                        .help("URL to check against")
                        .required(true)
                        .index(2),
                ),
        )
        .subcommand(
            SubCommand::with_name("android")
                .about("Android related checks")
                .arg(
                    Arg::with_name("apk")
                        .long("apk")
                        .value_name("FILE")
                        .help("APK to check against")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("app-id")
                        .value_name("APP_ID")
                        .help("App Identifier")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("URL")
                        .value_name("URL")
                        .help("URL to check against")
                        .required(true)
                        .index(2),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        ("ios", Some(m)) => cmd_ios(m),
        ("android", Some(m)) => cmd_android(m),
        _ => unimplemented!(),
    }
}

fn cmd_ios(matches: &ArgMatches) {
    let url = matches.value_of("URL").unwrap();
    let url: Uri = url.parse().expect("invalid url");

    if url.host().is_none() {
        panic!("URL must contain a host");
    }

    if let Some(ipa) = matches.value_of("ipa") {
        fs::metadata(ipa).expect("IPA file not found");
    }
    let bundle_identifier = matches.value_of("bundle-identifier").unwrap();

    println!("Running checks for link: {}", url);

    let aasa_uri = aasa::well_known_aasa_from_url(&url);
    let mut aasa = fetch_and_check_sync(aasa_uri, url.path(), bundle_identifier);
    if aasa.is_err() {
        let aasa_uri = aasa::root_aasa_from_url(&url);
        aasa = fetch_and_check_sync(aasa_uri, url.path(), bundle_identifier);
    }

    if aasa.is_err() {
        eprintln!("unable to fetch app association file");
        process::exit(-1);
    }

    let mut ipa_res = None;
    let mut entitlements = None;
    if let Some(ipa) = matches.value_of("ipa") {
        if let Some(entitlements_) = extract_info_from_ipa(ipa) {
            let problems = entitlements_.get_problems(bundle_identifier, url.host().unwrap());
            if problems.len() > 0 {
                ipa_res = Some(problems)
            }
            entitlements = Some(entitlements_);
        }
    }

    let aasa = aasa.ok().unwrap();
    let problems = aasa.get_problems();
    report::report_problems_human(Some(problems), Some(aasa), ipa_res, entitlements);
}

fn cmd_android(matches: &ArgMatches) {
    let url = matches.value_of("URL").unwrap();
    let url: Uri = url.parse().expect("invalid url");

    if url.host().is_none() {
        panic!("URL must contain a host");
    }
}

mod ios;
