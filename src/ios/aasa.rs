use bytes::BufMut;
use http::status;
use http::uri::Parts;
use http::Uri;
use hyper::rt::{Future, Stream};
use hyper::Client;
use hyper_tls::HttpsConnector;
use regex::Regex;
use regex_syntax::is_meta_character;
use std::io::Write;

#[derive(Debug)]
pub struct Match {
    bundle_id: String,
    pattern: String,
}

#[derive(Debug)]
pub struct AASACheck {
    //Input
    url: Uri,
    paths_to_check: Vec<String>,

    //Results
    ok_response: Option<bool>,
    content_type: Option<String>,
    file_size: Option<usize>,
    parsed: Option<Box<AppleAppSiteAssociation>>,
    parse_error: Option<bool>,
    matches: Option<Vec<Match>>,
}

impl AASACheck {
    fn new(url: Uri, paths_to_check: Vec<String>) -> Self {
        Self {
            url,
            paths_to_check,
            ok_response: None,
            content_type: None,
            file_size: None,
            parsed: None,
            parse_error: None,
            matches: None,
        }
    }

    fn content_type_json(&self) -> bool {
        if let Some(ref content_type) = self.content_type {
            content_type == "application/json"
        } else {
            false
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AppleAppSiteAssociation {
    applinks: AppLinks,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AppLinks {
    apps: Vec<String>,
    details: Vec<AppLinkDetail>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AppLinkDetail {
    appID: String,
    paths: Vec<String>,
}

pub fn aasa_match_path(pattern: &str, path: &str) -> bool {
    let not = pattern.starts_with("NOT ");
    let pat = if not { &pattern[4..] } else { pattern };
    if let Ok(re) = Regex::new(&regex_from_pattern(pat)) {
        if re.is_match(path) {
            if not {
                return false;
            }
            return true;
        }
    }
    false
}

#[test]
fn test_aasa_match_path() {
    assert!(aasa_match_path("*", "/foo"));
    assert!(!aasa_match_path("NOT *", "/foo"));
}

pub fn well_known_aasa_from_url(uri: &Uri) -> Uri {
    let host = uri.host().unwrap();
    let mut parts = Parts::default();
    parts.authority = Some(host.parse().unwrap());
    parts.path_and_query = Some("/.well-known/apple-app-site-association".parse().unwrap());
    parts.scheme = Some("https".parse().unwrap());

    Uri::from_parts(parts).unwrap()
}

pub fn root_aasa_from_url(uri: &Uri) -> Uri {
    let host = uri.host().unwrap();
    let mut parts = Parts::default();
    parts.authority = Some(host.parse().unwrap());
    parts.path_and_query = Some("/apple-app-site-association".parse().unwrap());
    parts.scheme = Some("https".parse().unwrap());

    Uri::from_parts(parts).unwrap()
}

#[test]
fn test_aasa_from_url() {
    assert_eq!(
        "https://example.com/.well-known/apple-app-site-association"
            .parse::<Uri>()
            .unwrap(),
        well_known_aasa_from_url(
            &"http://example.com/foo/bar?hello=world"
                .parse::<Uri>()
                .unwrap()
        )
    );
    assert_eq!(
        "https://example.com/apple-app-site-association"
            .parse::<Uri>()
            .unwrap(),
        root_aasa_from_url(
            &"http://example.com/foo/bar?hello=world"
                .parse::<Uri>()
                .unwrap()
        )
    );
}

// escape regex and replace * with .* and ? with .
fn regex_from_pattern(pattern: &str) -> String {
    let mut escaped = String::with_capacity(pattern.len());
    for c in pattern.chars() {
        match c {
            c if c == '*' => escaped.push_str(".*"),
            c if c == '?' => escaped.push('.'),
            c if is_meta_character(c) => {
                escaped.push('\\');
                escaped.push(c);
            }
            c => escaped.push(c),
        }
    }
    escaped
}

#[test]
fn test_regex_from_pattern() {
    assert_eq!("/foo/", regex_from_pattern("/foo/"));
    assert_eq!("/foo/.*", regex_from_pattern("/foo/*"));
    assert_eq!("/fo./.*", regex_from_pattern("/fo?/*"));
}

pub fn aasa_match(app: &AppLinkDetail, path: &str) -> bool {
    for pattern in &app.paths {
        if aasa_match_path(&pattern, path) {
            return true;
        }
    }
    false
}

// takes url to AASA file and path to check for handling, returns AppIDs that would match
pub fn fetch_and_check(
    aasa_uri: Uri,
    path_to_check: &str,
) -> impl Future<Item = AASACheck, Error = ()> {
    let https = HttpsConnector::new(4).unwrap();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let path_to_check = path_to_check.to_string();
    let mut check = AASACheck::new(aasa_uri.clone(), vec![path_to_check.clone()]);

    client
        .get(aasa_uri)
        .then(move |res| {
            if let Err(err) = res {
                check.ok_response = Some(false);
                return Err(check);
            }

            let res = res.unwrap();

            if res.status() != status::StatusCode::OK {
                check.ok_response = Some(false);
                return Err(check);
            }

            if let Some(header) = res.headers().get("Content-Type") {
                if let Ok(s) = header.to_str() {
                    check.content_type = Some(s.to_string());
                }
            }

            let buf = Vec::new();

            let data = res
                .into_body()
                .fold(buf.writer(), |mut buf, chunk| {
                    buf.write_all(&chunk).expect("failed writing");
                    Ok::<_, hyper::Error>(buf)
                })
                .wait();
            
            if data.is_err() {
                return Err(check);
            }

            let data = data.unwrap();
            check.file_size = Some(data.get_ref().len());

            match serde_json::from_slice::<AppleAppSiteAssociation>(data.get_ref()) {
                Ok(aasa) => {
                    check.parsed = Some(Box::new(aasa));
                }
                Err(_) => {
                    check.parse_error = Some(true);
                }
            }

            Ok(check)
        })
        // possibly check size here and abort further checks
        .and_then(|mut check| {
            let mut res: Vec<Match> = Vec::new();
            if let Some(ref parsed) = check.parsed {
                for app in &parsed.applinks.details {
                    for path_to_check in &check.paths_to_check {
                        if aasa_match(&app, &path_to_check[..]) {
                            let m = Match {
                                bundle_id: app.appID.clone(),
                                pattern: String::new(),
                            };
                            res.push(m);
                        }
                    }
                }
            }
            check.matches = Some(res);
            Ok(check)
        })
        .map_err(|err| {
            println!("{:?}", err);
        })
}
