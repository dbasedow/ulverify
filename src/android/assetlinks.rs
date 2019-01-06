use std::io::{self, Read};
use http::Uri;
use http::uri::Parts;

//TODO: check robots.txt

#[derive(Debug, Deserialize)]
pub struct AppTarget {
    namespace: String,
    package_name: String,
    sha256_cert_fingerprints: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Assetlink {
    relation: Vec<String>,
    target: AppTarget,
}

#[derive(Debug)]
pub enum Problem {
    ForbiddenByRobotsTxt,
    WrongStatusCode(u16),
    NoContentTypeHeader,
    WrongContentTypeHeader(String),
    InvalidFileFormat,
    AppIdNotInAssetlinks,
    MissingHandleAllUrlsRelation,
}

impl Problem {
    pub fn to_string_human(&self) -> String {
        match self {
            Problem::ForbiddenByRobotsTxt => "Access to assetlinks.json forbidden by robots.txt".to_string(),
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
            Problem::InvalidFileFormat => "Failed to parse file.".to_string(),
            Problem::AppIdNotInAssetlinks => "The app id you specified was not found in assetlinks.json.".to_string(),
            Problem::MissingHandleAllUrlsRelation => "The entry for the specified app id is missing the relation 'delegate_permission/common.handle_all_urls'.".to_string(),
        }
    }
}


pub fn assetlinks_json_from_url(uri: &Uri) -> Uri {
    let host = uri.host().unwrap();
    let mut parts = Parts::default();
    parts.authority = Some(host.parse().unwrap());
    parts.path_and_query = Some("/.well-known/assetlinks.json".parse().unwrap());
    parts.scheme = Some("https".parse().unwrap());

    Uri::from_parts(parts).unwrap()
}

#[test]
fn test_assetlinks_json_from_url() {
    assert_eq!(
        "https://example.com/.well-known/assetlinks.json"
            .parse::<Uri>()
            .unwrap(),
        assetlinks_json_from_url(
            &"http://example.com/foo/bar?hello=world"
                .parse::<Uri>()
                .unwrap()
        )
    );
}

#[derive(Debug)]
pub struct CheckResult {
    uri: Uri,
    app_id: String,
    status_code: Option<u16>,
    content_type: Option<String>,
    content: Option<Vec<u8>>,
    content_parsed: Option<Vec<Assetlink>>,
}

impl CheckResult {
    fn new(uri: Uri, app_id: String) -> Self {
        CheckResult {
            uri,
            app_id,
            status_code: None,
            content_type: None,
            content: None,
            content_parsed: None,
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

        if self.content.is_some() && self.content_parsed.is_none() {
            problems.push(Problem::InvalidFileFormat);
        }

        if let Some(ref assetlinks) = self.content_parsed {
            let matches: Vec<&Assetlink> = assetlinks.iter()
                .filter(|&assetlink| assetlink.target.package_name == self.app_id)
                .collect();
            if matches.is_empty() {
                problems.push(Problem::AppIdNotInAssetlinks);
            } else {
                let matches: Vec<&Assetlink> = matches.iter()
                    .filter(|&&assetlink| assetlink.relation.contains(&"delegate_permission/common.handle_all_urls".into()))
                    .map(|&assetlink| assetlink)
                    .collect();
                if matches.is_empty() {
                    problems.push(Problem::MissingHandleAllUrlsRelation);
                }
            }
        }

        problems
    }
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


pub fn fetch_and_check(uri: Uri, app_id: String) -> Result<CheckResult, Error> {
    let mut res = reqwest::get(&uri.to_string()[..])?;
    let mut check_res = CheckResult::new(uri, app_id);

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
        serde_json::from_slice::<Vec<Assetlink>>(check_res.content.as_ref().unwrap())?;

    check_res.content_parsed = Some(parsed);

    Ok(check_res)
}
