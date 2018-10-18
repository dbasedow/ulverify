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

#[derive(Serialize, Deserialize)]
pub struct AppleAppSiteAssociation {
    applinks: AppLinks,
}

#[derive(Serialize, Deserialize)]
pub struct AppLinks {
    apps: Vec<String>,
    details: Vec<AppLinkDetail>,
}

#[derive(Serialize, Deserialize)]
pub struct AppLinkDetail {
    appID: String,
    paths: Vec<String>,
}

#[derive(Debug)]
pub enum AppError {
    AASANotFound,
    ContentTypeNotSet,
    ContentTypeWrong(String),
    FileTooLarge(usize),
    InvalidFileFormat,
    NoMatchingPattern,
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
) -> impl Future<Item = Vec<String>, Error = ()> {
    let https = HttpsConnector::new(4).unwrap();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let path_to_check = path_to_check.to_string();

    client
        .get(aasa_uri)
        .then(|res| {
            if let Err(err) = res {
                return Err(AppError::AASANotFound);
            }

            let res = res.unwrap();

            if res.status() != status::StatusCode::OK {
                return Err(AppError::AASANotFound);
            }

            match res.headers().get("Content-Type") {
                Some(s) if s.as_bytes() != b"application/json" => {
                    return Err(AppError::ContentTypeWrong(s.to_str().unwrap().into()))
                }
                None => return Err(AppError::ContentTypeNotSet),
                _ => {}
            }

            res.into_body()
                .fold(vec![].writer(), |mut buf, chunk| {
                    buf.write_all(&chunk);
                    Ok::<_, hyper::Error>(buf)
                })
                .map_err(|_| AppError::AASANotFound)
                .wait()
        })
        .and_then(|res| {
            if res.get_ref().len() > 128_000 {
                return Err(AppError::FileTooLarge(res.get_ref().len()));
            }
            Ok(res)
        })
        .and_then(
            |data| match serde_json::from_slice::<AppleAppSiteAssociation>(data.get_ref()) {
                Ok(aasa) => Ok(aasa),
                Err(e) => Err(AppError::InvalidFileFormat),
            },
        )
        .and_then(move |aasa| {
            let mut res: Vec<String> = Vec::new();
            for app in aasa.applinks.details {
                if aasa_match(&app, &path_to_check) {
                    res.push(app.appID.clone());
                }
            }
            if res.len() == 0 {
                return Err(AppError::NoMatchingPattern);
            }
            Ok(res)
        })
        .map_err(|err| match err {
            AppError::AASANotFound => println!("Apple app site association not found"),
            AppError::ContentTypeWrong(s) => println!(
                "Content-Type header should be 'application/json' but was '{}'",
                s
            ),
            AppError::ContentTypeNotSet => {
                println!("Content-Type header not set MUST be 'application/json'")
            }
            AppError::FileTooLarge(s) => println!(
                "The Apple app site association file is too large: {} bytes but max is 128KB",
                s
            ),
            AppError::InvalidFileFormat => println!("Failed parsing the App site association file"),
            AppError::NoMatchingPattern => println!("No matching pattern found"),
        })
}
