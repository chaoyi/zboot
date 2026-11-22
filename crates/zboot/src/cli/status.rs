use super::run::{Invocation, json_response};

pub(super) fn status(
    datasets: Vec<String>,
    snapshots: bool,
    all: bool,
    devices: bool,
    inv: &mut Invocation,
    numbers: Option<&crate::status::Numbering>,
) -> Result<(), Box<dyn std::error::Error>> {
    let short = !all && datasets.is_empty() && !snapshots;
    let status = crate::status::observe(datasets, snapshots, devices)?;
    if inv.json {
        json_response(
            inv,
            crate::consent::Envelope::new(crate::consent::Outcome::Applied, None, &status),
        )?;
    } else if short {
        print!("{}", status.render_short_numbered(numbers));
    } else {
        print!("{}", status.render_numbered(numbers));
    }
    Ok(())
}
