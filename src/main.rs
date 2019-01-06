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
use crate::android::assetlinks;
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
        ("ios", Some(m)) => ios::run(m),
        ("android", Some(m)) => android::run(m),
        _ => unimplemented!(),
    }
}

mod ios;
mod android;
