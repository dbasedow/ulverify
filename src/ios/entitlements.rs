use mach_object::{LoadCommand, OFile};
use plist::Plist;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use zip::result::ZipError;

#[derive(Debug)]
pub struct Entitlements {
    pub application_identifier: Option<String>,
    pub associated_domains: Vec<String>,
}

impl Entitlements {
    fn new() -> Entitlements {
        Entitlements {
            application_identifier: None,
            associated_domains: Vec::new(),
        }
    }

    pub fn matches_applink_domain(&self, domain: &str) -> bool {
        for ad in &self.associated_domains {
            if ad.starts_with("applinks:") && &ad[9..] == domain {
                return true;
            }
        }

        false
    }

    pub fn get_problems(&self, app_id: &str, domain: &str) -> Vec<Problem> {
        let mut problems = Vec::new();
        if let Some(ref application_identifier) = self.application_identifier {
            if application_identifier != app_id {
                problems.push(Problem::WrongBundleIdentifier);
            }
        }
        if !self.matches_applink_domain(domain) {
            problems.push(Problem::DomainNotInApplinks);
        }
        problems
    }
}

pub enum Problem {
    DomainNotInApplinks,
    WrongBundleIdentifier,
}

impl Problem {
    pub fn to_string_human(&self) -> String {
        match self {
            Problem::DomainNotInApplinks => {
                "The domain is not listed in the entitlements.".to_string()
            }
            Problem::WrongBundleIdentifier => {
                "The bundle identifier in the entitlements does not match the one you supplied."
                    .to_string()
            }
        }
    }
}

pub fn extract_info_from_ipa(ipa: &str) -> Option<Entitlements> {
    if let Ok(buf) = extract_executable_from_ipa(ipa) {
        return extract_info_from_plist(&buf);
    }
    None
}

fn extract_executable_from_ipa(ipa: &str) -> zip::result::ZipResult<Vec<u8>> {
    let file = File::open(ipa)?;

    let mut zip = zip::ZipArchive::new(file)?;

    let mut candidates: Vec<(usize, usize)> = Vec::new();

    for i in 0..zip.len() {
        let file = zip.by_index(i).unwrap();
        if file.name().ends_with("/Info.plist") {
            candidates.push((i, file.name().len()));
        }
    }

    candidates.sort_by(|c1, c2| c1.1.cmp(&c2.1));

    // TODO: allocate with capacity from previous loops file size
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut file = zip.by_index(candidates[0].0)?;
        file.read_to_end(&mut buf)?;
    }

    let cur = Cursor::new(&buf[..]);

    if let Ok(Plist::Dictionary(parsed)) = Plist::read(cur) {
        if let Some(Plist::String(executable)) = parsed.get("CFBundleExecutable") {
            if let Some(Plist::String(bundle_name)) = parsed.get("CFBundleName") {
                let mut fname = vec![];
                write!(&mut fname, "Payload/{}.app/{}", bundle_name, executable)?;
                let fname = String::from_utf8(fname).unwrap();
                if let Ok(mut file) = zip.by_name(&fname) {
                    let mut buf = Vec::with_capacity(file.size() as usize);
                    if file.read_to_end(&mut buf).is_ok() {
                        return Ok(buf);
                    }
                }
            }
        }
    }

    Err(ZipError::FileNotFound)
}

pub fn extract_info_from_file(file_name: &str) -> Option<Entitlements> {
    let mut fp = File::open(file_name).unwrap();
    let mut buf = Vec::with_capacity(100);
    fp.read_to_end(&mut buf).expect("error reading file");
    extract_info_from_plist(&buf)
}

pub fn extract_info_from_plist(buf: &[u8]) -> Option<Entitlements> {
    if let Some(plist) = extract_entitlements_plist(&buf) {
        let cursor = Cursor::new(plist);
        if let Ok(Plist::Dictionary(parsed)) = Plist::read(cursor) {
            let mut entitlements = Entitlements::new();

            if let Some(Plist::String(app_id)) = parsed.get("application-identifier") {
                entitlements.application_identifier = Some(app_id.clone());
            }

            if let Some(Plist::Array(assoc_doms)) =
                parsed.get("com.apple.developer.associated-domains")
            {
                for dom in assoc_doms {
                    if let Plist::String(dom) = dom {
                        entitlements.associated_domains.push(dom.clone());
                    }
                }
            }

            return Some(entitlements);
        }
    }
    None
}

fn extract_entitlements_plist(buf: &[u8]) -> Option<&[u8]> {
    let mut cur = Cursor::new(&buf[..]);

    let mach_file = match OFile::parse(&mut cur).unwrap() {
        OFile::FatFile { files, .. } => {
            if files.is_empty() {
                panic!("FatFile with 0 architectures");
            }
            // return first MachFile from FatFile
            files[0].1.clone()
        }
        f @ OFile::MachFile { .. } => f,
        t => panic!("unknown Mach-O filetype {:?}", t),
    };

    if let OFile::MachFile { ref commands, .. } = mach_file {
        for cmd in commands {
            if let LoadCommand::CodeSignature(ldcmd) = cmd.command() {
                let start = ldcmd.off as usize;
                let end = ldcmd.off as usize + ldcmd.size as usize;
                let data = &buf[start..end];
                if let Some((offset, length)) = find_codesign_plist(data) {
                    let start = offset;
                    // the length contains the 4 magic bytes and the 4 length bytes
                    let end = offset + length - 8;
                    return Some(&data[start..end]);
                }
            }
        }
    }

    None
}

fn find_codesign_plist(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(offset) = find_codesign_magic_offset(buf) {
        let mut idx = offset + 4;
        let mut pl_len = (buf[idx] as usize) << 24;
        idx += 1;
        pl_len += (buf[idx] as usize) << 16;
        idx += 1;
        pl_len += (buf[idx] as usize) << 8;
        idx += 1;
        pl_len += buf[idx] as usize;
        idx += 1;
        return Some((idx, pl_len));
    }
    None
}

const MAGIC_BYTES: [u8; 4] = [0xfa, 0xde, 0x71, 0x71];

fn find_codesign_magic_offset(buf: &[u8]) -> Option<usize> {
    for (offset, window) in buf.windows(4).enumerate() {
        if window == MAGIC_BYTES {
            return Some(offset);
        }
    }
    None
}
