use mach_object::{LoadCommand, OFile, CPU_TYPE_ARM64};
use plist::Plist;
use std::io::{Cursor, Read, Write};

/*
fn main() {
    let file_name = env::args().last().unwrap();
    let mut fp = File::open(file_name).unwrap();
    let mut buf = Vec::with_capacity(100);
    let size = fp.read_to_end(&mut buf).unwrap();

    extract_entitlements_plist(&buf);
}
*/

pub fn extract_entitlements_plist(buf: &[u8]) {
    let mut cur = Cursor::new(&buf[..]);
    if let OFile::FatFile { ref files, .. } = OFile::parse(&mut cur).unwrap() {
        for (arch, fil) in files {
            if arch.cputype == CPU_TYPE_ARM64 {
                if let OFile::MachFile { ref commands, .. } = fil {
                    for cmd in commands {
                        match cmd.command() {
                            LoadCommand::CodeSignature(ldcmd) => {
                                let start = ldcmd.off as usize;
                                let end = ldcmd.off as usize + ldcmd.size as usize;
                                let data = &buf[start..end];
                                if let Some((offset, length)) = find_codesign_plist(data) {
                                    let start = offset;
                                    // the length contains the 4 magic bytes and the 4 length bytes
                                    let end = offset + length - 8;
                                    let cursor = Cursor::new(&data[start..end]);
                                    let pl = Plist::read(cursor);
                                    println!("{:?}", pl);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
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
