use clap::ArgMatches;
use http::Uri;
use std::process;

pub mod assetlinks;

pub fn run(matches: &ArgMatches) {
    let url = matches.value_of("URL").unwrap();
    let url: Uri = url.parse().expect("invalid url");

    if url.host().is_none() {
        panic!("URL must contain a host");
    }

    let app_id = matches.value_of("app-id").unwrap();

    let assetlinks_uri = assetlinks::assetlinks_json_from_url(&url);
    let mut assetlinks_res = assetlinks::fetch_and_check(assetlinks_uri, app_id.into());

    if assetlinks_res.is_err() {
        eprintln!("unable to fetch assetlinks file");
        process::exit(-1);
    }

    let assetlinks = assetlinks_res.unwrap();

    println!("{:#?}", assetlinks.get_problems());
}
