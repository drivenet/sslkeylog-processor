use std::path::PathBuf;

use anyhow::Result;

#[cfg(target_os = "windows")]
pub(crate) fn get_paths<'a, Patterns>(patterns: Patterns) -> Result<impl Iterator<Item = PathBuf>>
where
    Patterns: IntoIterator,
    Patterns::Item: AsRef<str> + 'a,
{
    Ok(patterns
        .into_iter()
        .map(|p| glob::glob(p.as_ref()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn get_paths<'a, Patterns>(patterns: Patterns) -> Result<impl Iterator<Item = PathBuf>>
where
    Patterns: IntoIterator,
    Patterns::Item: AsRef<str> + 'a,
{
    Ok(patterns.into_iter().map(|v| PathBuf::from(v.as_ref())))
}
