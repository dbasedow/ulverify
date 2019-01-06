use clap::ArgMatches;
use http::Uri;
use std::fs;
use crate::ios::aasa::fetch_and_check_sync;
use std::process;
use crate::ios::entitlements::extract_info_from_ipa;

pub mod aasa;
pub mod entitlements;
pub mod report;

pub fn run(matches: &ArgMatches) {
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
            if !problems.is_empty() {
                ipa_res = Some(problems)
            }
            entitlements = Some(entitlements_);
        }
    }

    let aasa = aasa.ok().unwrap();
    let problems = aasa.get_problems();
    report::report_problems_human(Some(problems), Some(aasa), ipa_res, entitlements);
}
