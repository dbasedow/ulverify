use apk_rs::apk::Apk;
use std::io;
use apk_rs::axml::XmlElementStream;
use http::Uri;
use apk_rs::axml::XmlEvent;
use regex::Regex;
use apk_rs::resources::resources::is_package_reference;
use apk_rs::typedvalue::TypedValue;
use apk_rs::axml::ElementStart;
use apk_rs::resources::resources::Resources;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
pub struct Authority {
    host: String,
    port: Option<u16>,
}

impl Authority {
    fn matches(&self, host: &str, port: Option<u16>) -> bool {
        self.host == host.to_string() && self.port == port
    }
}

#[derive(Debug, Clone)]
enum PathMatcher {
    Literal(String),
    Prefix(String),
    Pattern(Regex),
}

impl PathMatcher {
    fn matches(&self, path: &str) -> bool {
        match self {
            PathMatcher::Literal(p) => p == path,
            PathMatcher::Prefix(pre) => path.starts_with(pre),
            PathMatcher::Pattern(pattern) => match_pattern(path, pattern),
        }
    }
}

// algorithm from: https://github.com/aosp-mirror/platform_frameworks_base/blob/6bebb8418ceecf44d2af40033870f3aabacfe36e/core/java/android/os/PatternMatcher.java
fn match_pattern(path: &str, pattern: &str) -> bool {
    if pattern.len() == 0 {
        return path.len() == 0;
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let path: Vec<char> = path.chars().collect();
    let np = pattern.len();
    let nm = path.len();
    let mut ip = 0;
    let mut im = 0;
    let mut next_char = pattern[0];
    while ip < np && im < nm {
        let mut c = next_char;
        ip += 1;
        next_char = if ip < np { pattern[ip] } else { 0 as char };
        let escaped = c == '\\';
        if escaped {
            c = next_char;
            ip += 1;
            next_char = if ip < np { pattern[ip] } else { 0 as char };
        }
        if next_char == '*' {
            if !escaped && c == '.' {
                if ip >= np-1 {
                 return true;
                }
                ip += 1;

                next_char = pattern[ip];

                if next_char == '\\' {
                    ip += 1;
                    next_char = if ip < np { pattern[ip] } else { 0 as char };
                }
                loop {
                    if path[im] == next_char {
                        break;
                    }
                    im += 1;
                    if im >= nm {
                        break;
                    }
                }
                if im == nm {
                    return false;
                }
                ip += 1;
                next_char = if ip < np { pattern[ip] } else { 0 as char };
                im += 1;
            } else {
                loop {
                    if path[im] != c {
                        break;
                    }
                    im += 1;
                    if im >= nm {
                        break;
                    }
                }
                ip += 1;
                next_char = if ip < np { pattern[ip] } else { 0 as char };
            }
        } else {
            if c != '.' && path[im] != c {
                return false;
            }
            im += 1;
        }
    }

    if ip >= np && im >= nm {
        return true;
    }
    if ip == np - 2 && pattern[ip] == '.' && pattern[ip + 1] == '*' {
        return true;
    } 

    false
}

#[test]
fn test_match_pattern() {
    assert!(match_pattern("/", "/"));
    assert!(!match_pattern("/foo", "/bar"));    
    assert!(match_pattern("/", "/*"));
    assert!(!match_pattern("/foo", "/*")); // would match any number of slashes
    assert!(match_pattern("/foo", "/.*"));
    assert!(!match_pattern("/foo/bar/baz", "/.*/bar")); // this is what android does...
    assert!(!match_pattern("/foobarbaz", "/f.*baz")); // counter intuitive, but this is what android does...
}

#[derive(Debug, Clone)]
pub struct IntentFilter {
    activity_name: String,
    action: Vec<String>,
    category: Vec<String>,
    auto_verify: bool,
    schemes: Vec<String>,
    authorities: Vec<Authority>,
    path_matchers: Vec<PathMatcher>
}

impl IntentFilter {
    fn new(activity_name: String, auto_verify: bool) -> Self {
        Self {
            activity_name,
            action: Vec::new(),
            category: Vec::new(),
            auto_verify,
            schemes: Vec::new(),
            authorities: Vec::new(),
            path_matchers: Vec::new(),
        }
    }

    fn is_relevant(&self) -> bool {
        self.contains_http_scheme()
        && self.action.contains(&"android.intent.action.VIEW".to_string()) 
        && self.category.contains(&"android.intent.category.BROWSABLE".to_string())
    }

    fn contains_http_scheme(&self) -> bool {
        self.schemes.contains(&"http".to_string()) || self.schemes.contains(&"https".to_string())
    }

    fn contains_non_http_scheme(&self) -> bool {
        self.schemes.iter().filter(|&s| *s != "http".to_string() && *s != "https".to_string()).next().is_some()
    }

    fn matches_url(&self, url: Uri) -> bool {
        if let Some(scheme) = url.scheme_part() {
            if !self.schemes.contains(&scheme.to_string()) {
                return false;
            }
        }

        let mut auth_matches = false;
        if let Some(auth) = url.authority_part() {
            for authority in &self.authorities {
                if authority.matches(auth.host(), auth.port()) {
                    auth_matches = true;
                    break;
                }
            }
            if !auth_matches {
                return false;
            }
        }

        let mut path_matches = false;
        for matcher in &self.path_matchers {
            if matcher.matches(url.path()) {
                path_matches = true;
            }
        }
        if !path_matches {
            return false;
        }

        true
    }
}

#[test]
fn test_intent_filter_matching() {
    let filter = IntentFilter {
        activity_name: "foo".to_string(),
        auto_verify: true,
        action: vec!["android.intent.action.VIEW".to_string()],
        category: vec!["android.intent.category.BROWSABLE".to_string()],
        schemes: vec!["http".to_string(), "https".to_string()],
        authorities: vec![Authority { host: "example.com".to_string(), port: None }],
        path_matchers: vec![PathMatcher::Literal("/bar".to_string()), PathMatcher::Literal("/baz".to_string())],
    };
    assert!(filter.is_relevant());
    assert!(filter.matches_url(Uri::from_str("http://example.com/bar").unwrap()));
    assert!(!filter.matches_url(Uri::from_str("http://exemple.com/bar").unwrap()));
    assert!(!filter.matches_url(Uri::from_str("http://example.com:8080/bar").unwrap()));
}

#[derive(Debug)]
pub struct Manifest {
    intent_filters: Vec<IntentFilter>,
}

impl Manifest {
    fn new() -> Self {
        Self {
            intent_filters: Vec::new(),
        }
    }

    pub fn has_auto_verify(&self) -> bool {
        self.intent_filters
            .iter()
            .filter(|&f| f.auto_verify)
            .next()
            .is_some()
    }

    pub fn unique_authorities(&self) -> Vec<Authority> {
        let mut res = Vec::new();
        for filter in &self.intent_filters {
            for auth in &filter.authorities {
                if !res.contains(auth) {
                    res.push(auth.clone());
                }
            }
        }

        res
    }
}

#[derive(Debug)]
enum Problem {
    InvalidApk,
    MissingAutoVerifyInManifest,
    IntentFilterContainsHttpAndCustomScheme(IntentFilter), // if an intent-filter contains http and non http schemes, the hosts in that intent-filter will not be autoverified
    NoMatchingIntenFilter,
    MultipleMatchingIntentFilters

}

#[derive(Debug)]
pub struct CheckResult {
    app_id: String,
    signature: Vec<u8>,
    intent_filter: Vec<IntentFilter>,
}

pub fn check_apk(file_name: &str) -> io::Result<Manifest> {
    let apk_file = Apk::open(file_name)?;
    parse_manifest(&apk_file)
}

pub fn parse_manifest(apk: &Apk) -> io::Result<Manifest> {
    let f = apk.file_by_name("AndroidManifest.xml")?;
    if f.is_none() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "AndroidManifest.xml not found"));
    }
    let f = f.unwrap();
    let mut res: Vec<IntentFilter> = Vec::new();
    let mut data = Vec::with_capacity(f.len());
    let mut rdr = f.content()?;
    rdr.read_to_end(&mut data)?;
    let resources = apk.get_resources().unwrap();


    if let Ok(it) = XmlElementStream::new(&data) {
        let mut activity: Option<ElementStart> = None;
        let mut intent_filter: Option<IntentFilter> = None;
        for e in it {
            match e {
                XmlEvent::ElementStart(e) => {
                    match &e.name[..] {
                        "activity" => activity = Some(e),
                        "activity-alias" => activity = Some(e),
                        "intent-filter" if activity.is_some() => { // in case of intent-filter in <service> or <receiver> activity will be None
                            let activity_name = get_string_attribute(&activity.as_ref().unwrap(), "name", resources);
                            if let Some(activity_name) = activity_name {
                                intent_filter = Some(IntentFilter::new(activity_name, get_intent_filter_auto_verify(&e)));
                            }
                        }
                        "action" if intent_filter.is_some() => {
                            if let Some(action) = get_string_attribute(&e, "name", resources) {
                                let intent_filter = intent_filter.as_mut().unwrap();
                                intent_filter.action.push(action);
                            }
                        }
                        "data" if intent_filter.is_some() => {
                            if let Some(mut intent_filter) = intent_filter.as_mut() {
                                if let Some(scheme) = get_string_attribute(&e, "scheme", &resources) {
                                    intent_filter.schemes.push(scheme);
                                }

                                if let Some(host) = get_string_attribute(&e, "host", &resources) {
                                    let p =get_int_attribute(&e, "port", &resources);
                                    let port = if let Some(p) = get_int_attribute(&e, "port", &resources) {
                                        Some(p as u16)
                                    } else {
                                        None
                                    };

                                    intent_filter.authorities.push(Authority { 
                                        host, 
                                        port,
                                    });
                                }

                                if let Some(p) = get_string_attribute(&e, "path", &resources) {
                                    intent_filter.path_matchers.push(PathMatcher::Literal(p));
                                }
                                if let Some(p) = get_string_attribute(&e, "pathPrefix", &resources) {
                                    intent_filter.path_matchers.push(PathMatcher::Prefix(p));
                                }
                                if let Some(p) = get_string_attribute(&e, "pathPattern", &resources) {
                                    intent_filter.path_matchers.push(PathMatcher::Literal(p));
                                }
                            }
                        }
                        "category" if intent_filter.is_some() => {
                            if let Some(action) = get_string_attribute(&e, "name", resources) {
                                let intent_filter = intent_filter.as_mut().unwrap();
                                intent_filter.category.push(action);
                            }
                        }
                        _ => {}
                    }
                }
                XmlEvent::ElementEnd(e) => {
                    match &e.name[..] {
                        "activity" => activity = None,
                        "intent-filter" => {
                            if let Some(ref intent_filter) = intent_filter {
                                if intent_filter.is_relevant() {
                                    res.push(intent_filter.clone());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
    Ok(Manifest { intent_filters: res })
}

fn get_string_attribute(element: &ElementStart, field_name: &str, resources: &Resources) -> Option<String> {
    if element.attribute_len() > 0 {
        for a in element.attributes.as_ref().unwrap() {
            if a.name == field_name {
                let s = if a.value.is_reference_type() {
                    match a.value {
                        TypedValue::Reference(r) if is_package_reference(r) => resources.get_human_reference(r).unwrap(),
                        TypedValue::Reference(_) => a.value.to_string(),
                        _ => "".to_string(),
                    }
                } else {
                    a.value.to_string()
                };
                return Some(s);
            }
        }
    }

    None
}

fn get_intent_filter_auto_verify(intent_filter: &ElementStart) -> bool {
    if intent_filter.attribute_len() > 0 {
        for a in intent_filter.attributes.as_ref().unwrap() {
            if a.name == "autoVerify" {
                if let TypedValue::Boolean(b) = a.value {
                    return b;
                }
            }
        }
    }

    false
}


fn get_int_attribute(element: &ElementStart, field_name: &str, resources: &Resources) -> Option<i32> {
    if element.attribute_len() > 0 {
        for a in element.attributes.as_ref().unwrap() {
            if a.name == field_name {
                if let TypedValue::IntDecimal(d) = a.value {
                    return Some(d);
                }
            }
        }
    }

    None
}
