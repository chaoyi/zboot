use super::run::json_response;

pub(super) fn status(
    datasets: Vec<String>,
    snapshots: bool,
    all: bool,
    devices: bool,
    json: bool,
    numbers: Option<&crate::status::Numbering>,
) -> Result<(), Box<dyn std::error::Error>> {
    let short = !all && datasets.is_empty() && !snapshots;
    let status = crate::status::observe(datasets, snapshots, devices)?;
    if json {
        json_response(crate::consent::Envelope::new(
            crate::consent::Outcome::Applied,
            None,
            &status,
        ))?;
    } else if short {
        print!("{}", status.render_short_numbered(numbers));
    } else {
        print!("{}", status.render_numbered(numbers));
    }
    Ok(())
}

pub(super) fn trace(
    cmdline: std::path::PathBuf,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut value = String::new();
    std::fs::File::open(&cmdline)
        .and_then(|file| file.take(65537).read_to_string(&mut value))
        .map_err(crate::output::naming("--cmdline", &cmdline))?;
    if value.len() > 65536 {
        return Err("kernel command-line input exceeds trace limit".into());
    }
    let trace = crate::trace::Trace::from_cmdline(&value)?
        .ok_or("no Zboot handoff trace in selected kernel command line")?;
    if json {
        json_response(crate::consent::Envelope::new(
            crate::consent::Outcome::Applied,
            None,
            &trace,
        ))?;
    } else {
        print!("{}", trace.render());
    }

    Ok(())
}
