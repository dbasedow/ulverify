use crate::ios::aasa::AASACheck;
use std::io::{self, Write};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

pub fn report_aasa_human(aasa: &AASACheck) -> io::Result<()> {
    let mut skip = false;

    let mut stdout = StandardStream::stdout(ColorChoice::Always);

    let mut green = ColorSpec::new();
    green.set_fg(Some(Color::Green));

    let mut red = ColorSpec::new();
    red.set_fg(Some(Color::Red));

    match aasa.ok_response {
        Some(ok) if ok => {
            stdout.set_color(&green)?;
            writeln!(&mut stdout, "\u{2714} Fetching {} succeeded", aasa.url)?;
        }
        _ => {
            stdout.set_color(&red)?;
            writeln!(&mut stdout, "\u{2757} Fetching {} failed", aasa.url)?;
            skip = true;
        }
    }
    stdout.reset()?;

    if !skip {
        match aasa.content_type {
            Some(ref ct) if ct == "application/json" => {
                stdout.set_color(&green)?;
                writeln!(
                    &mut stdout,
                    "\u{2714} Content-Type header is 'application/json'"
                )?;
            }
            Some(ref ct) => {
                stdout.set_color(&red)?;
                writeln!(
                    &mut stdout,
                    "\u{2757} Content-Type header is '{}', but MUST be 'application/json'",
                    ct
                )?;
            }
            None => {
                stdout.set_color(&red)?;
                writeln!(
                    &mut stdout,
                    "\u{2757} Content-Type header is not set, but MUST be 'application/json'"
                )?;
            }
        }
        stdout.reset()?;
    }

    if !skip {
        match aasa.file_size {
            Some(s) if s < 128_000 => {
                stdout.set_color(&green)?;
                println!("\u{2714} Filesize is under 128 KB ({})", s);
            }
            Some(s) => {
                stdout.set_color(&red)?;
                println!("\u{2757} Filesize is {} but MUST be under 128 KB", s);
            }
            _ => {}
        }
        stdout.reset()?;
    }

    if !skip {
        match aasa.parse_error {
            Some(e) if e => {
                stdout.set_color(&red)?;
                println!("\u{2757} Parsing the file failed");
                skip = true;
            }
            _ => {
                stdout.set_color(&green)?;
                println!("\u{2714} Parsing the file was successful");
            }
        }
        stdout.reset()?;
    }

    if !skip {
        if aasa.has_matches() {
            stdout.set_color(&green)?;
            println!("\u{2714} Matches found:");
            stdout.reset()?;
            for mat in aasa.matches.as_ref().unwrap() {
                println!("  {} ({})", mat.bundle_id, mat.pattern);
            }
        } else {
            stdout.set_color(&red)?;
            println!("\u{2757} No matches found");
        }
    }

    Ok(())
}
