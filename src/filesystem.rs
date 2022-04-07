use std::path::PathBuf;

use anyhow::Result;

pub(crate) fn get_paths<Patterns>(patterns: Patterns) -> Result<impl Iterator<Item = PathBuf>>
where
    Patterns: IntoIterator,
    Patterns::Item: AsRef<str>,
{
    #[cfg(windows)]
    {
        let mut result = Vec::new();
        for pattern in patterns {
            for path in glob::glob(pattern.as_ref())? {
                result.push(path?);
            }
        }

        Ok(result.into_iter())
    }
    #[cfg(not(windows))]
    Ok(patterns.into_iter().map(|v| PathBuf::from(v.as_ref())))
}
