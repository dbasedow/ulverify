use http::uri::Parts;
use http::Uri;
use regex::Regex;
use regex_syntax::is_meta_character;
use std::io;
use std::io::Read;

#[derive(Debug)]
pub struct Match {
    pub bundle_id: String,
    pub pattern: String,
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

impl AppLinkDetail {
    fn matches(&self, app_id: &str) -> bool {
        if let Some(team_id_end) = self.appID.find('.') {
            let app_id_no_team = &self.appID[team_id_end + 1..];
            return app_id_no_team == app_id;
        }
        false
    }
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

pub fn aasa_match(app: &AppLinkDetail, path: &str) -> Option<String> {
    for pattern in &app.paths {
        if aasa_match_path(&pattern, path) {
            return Some(pattern.to_string());
        }
    }
    None
}

#[derive(Debug)]
pub enum Error {
    FetchFailed,
    ParseFailed(serde_json::Error),
}

impl From<reqwest::Error> for Error {
    fn from(_: reqwest::Error) -> Self {
        Error::FetchFailed
    }
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::FetchFailed
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::ParseFailed(e)
    }
}

#[derive(Debug)]
pub enum Problem {
    WrongStatusCode(u16),
    NoContentTypeHeader,
    WrongContentTypeHeader(String),
    ContentTooLarge(usize),
    InvalidFileFormat,
    NoMatch,
}

impl Problem {
    pub fn to_string_human(&self) -> String {
        match self {
            Problem::WrongStatusCode(sc) if *sc == 301 || *sc == 302 => {
                format!("Invalid status code '{}'. Redirects are not allowed.", sc)
            }
            Problem::WrongStatusCode(sc) => format!("Invalid status code '{}'.", sc),
            Problem::NoContentTypeHeader => {
                "No 'Content-Type' HTTP header sent. Must be 'application/json'.".to_string()
            }
            Problem::WrongContentTypeHeader(ct) => format!(
                "Wrong 'Content-Type' header sent: '{}'. Must be 'application/json'",
                ct
            ),
            Problem::ContentTooLarge(s) => format!(
                "File too large {} bytes (uncompressed). Maximum allowed is 128KB",
                s
            ),
            Problem::InvalidFileFormat => "Failed to parse file.".to_string(),
            Problem::NoMatch => "No bundle id, path combination matches your request.".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct CheckResult {
    uri: Uri,
    path_to_check: String,
    app_id: String,
    status_code: Option<u16>,
    content_type: Option<String>,
    content: Option<Vec<u8>>,
    content_parsed: Option<AppleAppSiteAssociation>,
    matches: Option<Vec<Match>>,
}

impl CheckResult {
    fn new(uri: Uri, path_to_check: String, app_id: String) -> Self {
        CheckResult {
            uri,
            path_to_check,
            app_id,
            status_code: None,
            content_type: None,
            content: None,
            content_parsed: None,
            matches: None,
        }
    }

    pub fn get_problems(&self) -> Vec<Problem> {
        let mut problems = Vec::new();
        if let Some(sc) = self.status_code {
            if sc != 200 {
                problems.push(Problem::WrongStatusCode(sc));
            }
        }

        if let Some(ref ct) = self.content_type {
            if ct != "application/json" {
                problems.push(Problem::WrongContentTypeHeader(ct.to_string()));
            }
        } else {
            problems.push(Problem::NoContentTypeHeader);
        }

        if let Some(ref content) = self.content {
            if content.len() > 128_000 {
                problems.push(Problem::ContentTooLarge(content.len()));
            }
        }

        if self.content.is_some() && self.content_parsed.is_none() {
            problems.push(Problem::InvalidFileFormat);
        }

        if let Some(ref matches) = self.matches {
            if matches.is_empty() {
                problems.push(Problem::NoMatch);
            }
        }

        problems
    }
}

pub fn fetch_and_check_sync(
    aasa_uri: Uri,
    path_to_check: &str,
    app_id: &str,
) -> Result<CheckResult, Error> {
    let mut res = reqwest::get(&aasa_uri.to_string()[..])?;
    let mut check_res = CheckResult::new(aasa_uri, path_to_check.to_string(), app_id.to_string());

    check_res.status_code = Some(res.status().as_u16());
    if let Some(ct) = res.headers().get("Content-Type") {
        check_res.content_type = Some(ct.to_str().unwrap().to_string());
    }

    if res.status().as_u16() != 200 {
        return Ok(check_res);
    }

    let mut buf = Vec::with_capacity(500);
    res.read_to_end(&mut buf)?;
    check_res.content = Some(buf);

    let parsed =
        serde_json::from_slice::<AppleAppSiteAssociation>(check_res.content.as_ref().unwrap())?;

    let mut res: Vec<Match> = Vec::new();
    for app in parsed.applinks.details.iter().filter(|a| a.matches(app_id)) {
        if let Some(pat) = aasa_match(&app, &path_to_check[..]) {
            let m = Match {
                bundle_id: app.appID.clone(),
                pattern: pat,
            };
            res.push(m);
        }
    }
    check_res.matches = Some(res);
    check_res.content_parsed = Some(parsed);

    Ok(check_res)
}
