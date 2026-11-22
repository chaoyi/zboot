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
