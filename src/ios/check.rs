use clap::ArgMatches;
use crate::ios::aasa::AASACheck;
use crate::ios::entitlements::Entitlements;
use http::Uri;

// TODO: make it a future
pub struct IOSCheck {
    url: Uri,
    bundle_identifier: Option<String>,
    ipa: Option<String>,
    entitlements: Option<Entitlements>,
    aasa_check: Option<AASACheck>,
}

impl IOSCheck {
    fn from_cli_args(args: &ArgMatches) -> Self {
        let url = args.value_of("URL").unwrap();
        let url: Uri = url.parse().expect("invalid url");

        if url.host().is_none() {
            panic!("URL must contain a host");
        }

        let mut bundle_identifier = None;
        if let Some(supplied) = args.value_of("bundle-identifier") {
            bundle_identifier = Some(supplied.to_string());
        }

        let mut ipa = None;
        if let Some(fname) = args.value_of("ipa") {
            ipa = Some(fname.to_string());
        }

        IOSCheck {
            url,
            bundle_identifier,
            ipa,
            entitlements: None,
            aasa_check: None,
        }
    }
}
