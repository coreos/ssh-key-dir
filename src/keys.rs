// Copyright 2020 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fs::{metadata, read_dir, DirEntry, OpenOptions};
use std::io::{self, copy, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use uzers::get_effective_uid;

const KEYS_SUBDIR: &str = "authorized_keys.d";

pub(crate) fn read_keys(ssh_dir: &Path, out: &mut impl Write, err: &mut impl Write) -> Result<()> {
    // if there's no KEYS_SUBDIR, log a message for debugging and return
    // successfully
    let authorized_keys_dir = ssh_dir.join(KEYS_SUBDIR);
    if !authorized_keys_dir.exists() {
        err.write_all(format!("{} does not exist\n", authorized_keys_dir.display()).as_bytes())?;
        return Ok(());
    }

    // check permissions on paths leading to KEYS_SUBDIR
    // unlike sshd, we don't check permissions on $HOME
    ensure_safe_permissions(ssh_dir)?;
    ensure_safe_permissions(&authorized_keys_dir)?;

    // read directory in lexical order
    let mut entries = read_dir(&authorized_keys_dir)
        .with_context(|| format!("reading {}", authorized_keys_dir.display()))?
        .collect::<Vec<_>>();
    entries.sort_unstable_by(|a, b| {
        a.as_ref()
            .map(|ent| ent.path())
            .unwrap_or_else(|_| PathBuf::new())
            .cmp(
                &b.as_ref()
                    .map(|ent| ent.path())
                    .unwrap_or_else(|_| PathBuf::new()),
            )
    });

    for ent in entries {
        // Report and ignore errors for individual files, so we don't lock
        // the user out of their account.
        match try_read_key_file(&authorized_keys_dir, ent, out) {
            Ok(_) => (),
            Err(e) => {
                let _ = err.write_all(format!("Error: {e:#}\n").as_bytes());
            }
        };
    }

    Ok(())
}

// Ensure that the specified path is owned by root or the current user, and
// that it isn't group- or other-writable.  Roughly matches sshd's checks for
// authorized_keys files.
// https://github.com/openssh/openssh-portable/blob/7fafaeb5da36/misc.c#L2020-L2089
fn ensure_safe_permissions(path: &Path) -> Result<()> {
    let metadata = path
        .metadata()
        .with_context(|| format!("couldn't stat {}", path.display()))?;

    // owned by user or root
    let uid = metadata.uid();
    if uid != 0 && uid != get_effective_uid() {
        bail!("bad ownership on {}: {}", path.display(), uid);
    }

    // not writable by group/other
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o022 != 0 {
        bail!(
            "bad permission on {}: {:04o} & 0022 != 0",
            path.display(),
            mode
        );
    }
    Ok(())
}

fn try_read_key_file(
    dir_path: &Path,
    ent: io::Result<DirEntry>,
    out: &mut impl Write,
) -> Result<()> {
    // unpack error
    let ent = ent.with_context(|| format!("reading {}", dir_path.display()))?;

    // ignore dotfiles
    if ent.file_name().into_vec()[0] == b'.' {
        bail!("{} is a dotfile, ignoring", ent.path().display());
    }

    // check file type and permissions
    if !metadata(ent.path())
        .with_context(|| format!("couldn't stat {}", ent.path().display()))?
        .is_file()
    {
        bail!("{} is not a file, ignoring", ent.path().display());
    }
    ensure_safe_permissions(&ent.path())?;

    // open file
    let mut file = OpenOptions::new()
        .read(true)
        .open(ent.path())
        .with_context(|| format!("opening {}", ent.path().display()))?;

    // write comment with source path
    let safe_path = ent.path().to_string_lossy().replace('\n', "\u{fffd}");
    out.write_all(format!("# {safe_path}\n").as_bytes())
        .with_context(|| format!("writing header for {}", ent.path().display()))?;

    // Copy file contents, ensuring output is newline-terminated even if the
    // file isn't, or if copy() fails partway.  Also add an extra newline to
    // separate files from each other.  Return first error.
    let result = copy(&mut file, out).with_context(|| format!("copying {}", ent.path().display()));
    result
        .and(out.write_all(&[b'\n', b'\n']).context("writing newlines"))
        .map(|_count| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::{create_dir, create_dir_all, set_permissions, Permissions};
    use std::io::Cursor;
    use std::os::unix::fs::symlink;

    use nix::sys::stat;
    use nix::unistd::mkfifo;
    use tempfile::{Builder, TempDir};

    fn make_file(path: &Path, contents: &str) -> Result<()> {
        let mut file = OpenOptions::new().create(true).write(true).open(path)?;
        file.write_all(contents.as_bytes())?;
        set_permissions(path, Permissions::from_mode(0o644))?;
        Ok(())
    }

    fn make_dir(path: &Path) -> Result<()> {
        create_dir(path)?;
        set_permissions(path, Permissions::from_mode(0o755))?;
        Ok(())
    }

    fn make_ssh_dir() -> Result<TempDir> {
        let dir = Builder::new().prefix("ssh-key-dir").tempdir()?;
        set_permissions(dir.path(), Permissions::from_mode(0o700))?;
        let keydir = dir.path().join(KEYS_SUBDIR);
        make_dir(&keydir)?;

        // regular file, multiple lines
        make_file(&keydir.join("b"), "file-b\nfile-b2\n")?;
        // regular file, no trailing newline
        make_file(&keydir.join("a"), "file-a-no-newline")?;
        // unreadable file
        make_file(&keydir.join("c"), "file-c")?;
        set_permissions(keydir.join("c"), Permissions::from_mode(0o0))?;
        // empty file
        make_file(&keydir.join("e"), "")?;
        // dotfile
        make_file(&keydir.join(".h"), "file-h")?;
        // filename with newline
        make_file(&keydir.join("nl\nnl"), "file-nl")?;
        // directory
        make_dir(&keydir.join("d"))?;
        // unreadable directory
        make_dir(&keydir.join("dnp"))?;
        set_permissions(keydir.join("dnp"), Permissions::from_mode(0o0))?;
        // symlink to file
        symlink(keydir.join("a"), keydir.join("sf"))?;
        // symlink to directory
        symlink(keydir.join("d"), keydir.join("sd"))?;
        // dangling symlink
        symlink(keydir.join("nx"), keydir.join("snx"))?;
        // fifo
        mkfifo(&keydir.join("fifo"), stat::Mode::S_IRUSR)?;

        Ok(dir)
    }

    fn do_read_keys(ssh_dir: &Path, expected_out: &str, expected_err: &str) -> Result<()> {
        let mut out = Cursor::new(Vec::<u8>::new());
        let mut err = Cursor::new(Vec::<u8>::new());
        let result = read_keys(ssh_dir, &mut out, &mut err);
        assert_eq!(
            String::from_utf8_lossy(&err.into_inner()),
            expected_err,
            "stderr mismatch"
        );
        assert_eq!(
            String::from_utf8_lossy(&out.into_inner()),
            expected_out,
            "stdout mismatch"
        );
        result
    }

    #[test]
    fn test_read_keys() {
        if get_effective_uid() == 0 {
            panic!("can't run tests as root");
        }

        let dir = make_ssh_dir().expect("make_ssh_dir() failed");
        let formatted_dir = dir.path().join(KEYS_SUBDIR).to_string_lossy().into_owned();
        do_read_keys(
            dir.path(),
            &format!(
                "# {formatted_dir}/a
file-a-no-newline

# {formatted_dir}/b
file-b
file-b2


# {formatted_dir}/e


# {formatted_dir}/nl\u{fffd}nl
file-nl

# {formatted_dir}/sf
file-a-no-newline

"
            ),
            &format!(
                "Error: {formatted_dir}/.h is a dotfile, ignoring
Error: opening {formatted_dir}/c: Permission denied (os error 13)
Error: {formatted_dir}/d is not a file, ignoring
Error: {formatted_dir}/dnp is not a file, ignoring
Error: {formatted_dir}/fifo is not a file, ignoring
Error: {formatted_dir}/sd is not a file, ignoring
Error: couldn't stat {formatted_dir}/snx: No such file or directory (os error 2)
"
            ),
        )
        .expect("read_keys() failed");
    }

    #[test]
    fn test_empty_dir() {
        let tempdir = Builder::new().prefix("ssh-key-dir").tempdir().unwrap();
        set_permissions(tempdir.path(), Permissions::from_mode(0o700)).unwrap();
        let path = tempdir.path().join(KEYS_SUBDIR);
        make_dir(&path).unwrap();
        do_read_keys(tempdir.path(), "", "").unwrap();
    }

    #[test]
    fn test_perms() {
        let tempdir = Builder::new().prefix("ssh-key-dir").tempdir().unwrap();

        // unreadable SSH dir
        let path = tempdir.path().join("a");
        make_dir(&path).unwrap();
        set_permissions(&path, Permissions::from_mode(0o0)).unwrap();
        do_read_keys(
            &path,
            "",
            &format!(
                "{} does not exist\n",
                path.join(KEYS_SUBDIR).to_string_lossy()
            ),
        )
        .unwrap();

        // unreadable KEYS_SUBDIR
        let path = tempdir.path().join("b");
        let subdir = path.join(KEYS_SUBDIR);
        create_dir_all(&subdir).unwrap();
        set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
        set_permissions(&subdir, Permissions::from_mode(0o0)).unwrap();
        assert_eq!(
            do_read_keys(&path, "", "").unwrap_err().to_string(),
            format!("reading {}", subdir.display())
        );

        // unreadable key
        let path = tempdir.path().join("c");
        let subdir = path.join(KEYS_SUBDIR);
        let file = subdir.join("z");
        create_dir_all(&subdir).unwrap();
        make_file(&file, "contents").unwrap();
        set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
        set_permissions(&subdir, Permissions::from_mode(0o700)).unwrap();
        set_permissions(&file, Permissions::from_mode(0o0)).unwrap();
        do_read_keys(
            &path,
            "",
            &format!(
                "Error: opening {}: Permission denied (os error 13)\n",
                file.to_string_lossy()
            ),
        )
        .unwrap();

        // bad SSH dir permissions
        let path = tempdir.path().join("d");
        let subdir = path.join(KEYS_SUBDIR);
        create_dir_all(subdir).unwrap();
        set_permissions(&path, Permissions::from_mode(0o775)).unwrap();
        assert_eq!(
            do_read_keys(&path, "", "").unwrap_err().to_string(),
            format!("bad permission on {}: 0775 & 0022 != 0", path.display())
        );

        // bad KEYS_SUBDIR permissions
        let path = tempdir.path().join("e");
        let subdir = path.join(KEYS_SUBDIR);
        create_dir_all(&subdir).unwrap();
        set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
        set_permissions(&subdir, Permissions::from_mode(0o775)).unwrap();
        assert_eq!(
            do_read_keys(&path, "", "").unwrap_err().to_string(),
            format!("bad permission on {}: 0775 & 0022 != 0", subdir.display())
        );

        // bad key permissions
        let path = tempdir.path().join("f");
        let subdir = path.join(KEYS_SUBDIR);
        let file = subdir.join("z");
        create_dir_all(&subdir).unwrap();
        make_file(&file, "contents").unwrap();
        set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
        set_permissions(&subdir, Permissions::from_mode(0o700)).unwrap();
        set_permissions(&file, Permissions::from_mode(0o664)).unwrap();
        do_read_keys(
            &path,
            "",
            &format!(
                "Error: bad permission on {}: 0664 & 0022 != 0\n",
                file.to_string_lossy()
            ),
        )
        .unwrap();

        // SSH dir is a file
        let path = tempdir.path().join("g");
        make_file(&path, "").unwrap();
        set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
        do_read_keys(
            &path,
            "",
            &format!(
                "{} does not exist\n",
                path.join(KEYS_SUBDIR).to_string_lossy()
            ),
        )
        .unwrap();

        // KEYS_SUBDIR is a file
        let path = tempdir.path().join("h");
        create_dir_all(&path).unwrap();
        let subdir = path.join(KEYS_SUBDIR);
        make_file(&subdir, "").unwrap();
        set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
        set_permissions(&subdir, Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            do_read_keys(&path, "", "").unwrap_err().to_string(),
            format!("reading {}", subdir.display())
        );

        // missing SSH dir
        let path = tempdir.path().join("i");
        do_read_keys(
            &path,
            "",
            &format!(
                "{} does not exist\n",
                path.join(KEYS_SUBDIR).to_string_lossy()
            ),
        )
        .unwrap();

        // missing KEYS_SUBDIR
        let path = tempdir.path().join("j");
        create_dir_all(&path).unwrap();
        do_read_keys(
            &path,
            "",
            &format!(
                "{} does not exist\n",
                path.join(KEYS_SUBDIR).to_string_lossy()
            ),
        )
        .unwrap();
    }
}
