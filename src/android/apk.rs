use apk_rs::apk::Apk;
use std::io;
use apk_rs::axml::XmlElementStream;
use apk_rs::axml::XmlEvent;
use apk_rs::resources::resources::is_package_reference;
use apk_rs::typedvalue::TypedValue;
use apk_rs::axml::ElementStart;
use apk_rs::resources::resources::Resources;

#[derive(Debug)]
pub struct IntentFilterData {
    scheme: Option<String>,
    host: Option<String>,
    port: Option<String>,
    path: Option<String>,
    path_pattern: Option<String>,
    path_prefix: Option<String>,
}

impl IntentFilterData {
    fn new() -> Self {
        Self {
            scheme: None,
            host: None,
            port: None,
            path: None,
            path_pattern: None,
            path_prefix: None,
        }
    }
}

#[derive(Debug)]
struct IntentFilter {
    activity_name: String,
    pub action: Vec<String>,
    category: Vec<String>,
    auto_verify: bool,
    data: Option<Vec<IntentFilterData>>,
}

impl IntentFilter {
    fn new(activity_name: String, auto_verify: bool) -> Self {
        Self {
            activity_name,
            action: Vec::new(),
            category: Vec::new(),
            auto_verify,
            data: None,
        }
    }
}

#[derive(Debug)]
enum Problem {
    InvalidApk,
    MissingAutoVerifyInManifest,

}

#[derive(Debug)]
pub struct CheckResult {
    app_id: String,
    signature: Vec<u8>,
    intent_filter: Vec<IntentFilter>,
}

pub fn check_apk(file_name: &str) -> io::Result<Vec<IntentFilterData>> {
    let apk_file = Apk::open(file_name)?;
    parse_manifest(&apk_file)
}

pub fn parse_manifest(apk: &Apk) -> io::Result<Vec<IntentFilterData>> {
    let f = apk.file_by_name("AndroidManifest.xml")?;
    if f.is_none() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "AndroidManifest.xml not found"));
    }
    let f = f.unwrap();
    let mut res: Vec<IntentFilterData> = Vec::new();
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
                        "intent-filter" => {
                            let activity_name = get_string_attribute(&activity.as_ref().unwrap(), "name", resources);
                            if let Some(activity_name) = activity_name {
                                intent_filter = Some(IntentFilter::new(activity_name, get_intent_filter_auto_verify(&e)));
                            }
                        }
                        "action" if intent_filter.is_some() => {
                            if let Some(action) = get_string_attribute(&e, "name", resources) {
                                let mut intent_filter = intent_filter.as_mut().unwrap();
                                intent_filter.action.push(action);
                            }
                        }
                        "data" if intent_filter.is_some() => {} //TODO: implement
                        "category" if intent_filter.is_some() => {
                            if let Some(action) = get_string_attribute(&e, "name", resources) {
                                let mut intent_filter = intent_filter.as_mut().unwrap();
                                intent_filter.category.push(action);
                            }
                        } //TODO: implement
                        _ => {}
                    }
                }
                XmlEvent::ElementEnd(e) => {
                    println!("</{}>", e.name);
                }
                _ => {}
            }
        }
    }
    Ok(res)
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
