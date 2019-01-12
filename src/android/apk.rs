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

#[derive(Debug, Clone, PartialEq)]
pub struct Authority {
    host: String,
    port: Option<i32>,
}

#[derive(Debug, Clone)]
enum PathMatcher {
    Literal(String),
    Prefix(String),
    Pattern(Regex),
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
        (self.schemes.contains(&"http".to_string()) || self.schemes.contains(&"https".to_string()))
        && self.action.contains(&"android.intent.action.VIEW".to_string()) 
        && self.category.contains(&"android.intent.category.BROWSABLE".to_string())
    }

    fn matches_url(&self, url: Uri) -> bool {
        // self.schemes.contains(url.scheme())
        // self.authorities.contains(url.host() + url.port())
        // for m in self.path_matchers { m.match(url.path) }
        true
    }
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
                                    intent_filter.authorities.push(Authority { 
                                        host, 
                                        port: get_int_attribute(&e, "port", &resources) 
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
