use clap::ArgMatches;
use crate::ios::entitlements::{self, Entitlements};
use http::Uri;
use tokio::prelude::*;

pub struct IPACheckResult {
    pub bundle_identifier: Option<String>,
    pub entitlements: Option<Entitlements>,
}

pub struct IPACheck {
    pub url: Uri,
    pub bundle_identifier: Option<String>,
    pub ipa: Option<String>,
}

impl IPACheck {
    pub fn from_cli_args(args: &ArgMatches) -> Self {
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

        IPACheck {
            url,
            bundle_identifier,
            ipa,
        }
    }
}

impl Future for IPACheck {
    type Item = IPACheckResult;
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut res = IPACheckResult {
            bundle_identifier: self.bundle_identifier.clone(),
            entitlements: None,
        };
        if self.ipa.is_some() {
            if let Some(ents) = entitlements::extract_info_from_ipa(self.ipa.as_ref().unwrap()) {
                res.entitlements = Some(ents);
            }
        }
        Ok(Async::Ready(res))
    }
}
