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

use std::ffi::{OsStr, OsString};
use std::io;

use anyhow::{Context, Result};
use clap::{crate_version, value_parser, Arg, Command};
use uzers::os::unix::UserExt;
use uzers::switch::{switch_user_group, SwitchUserGuard};
use uzers::{get_current_username, get_user_by_name, User};

use crate::keys::read_keys;

mod keys;

struct Config {
    username: OsString,
}

fn make_clap(current_user: OsString) -> Command {
    // Args are listed in --help in the order declared here.  Please keep
    // the entire help text to 80 columns.
    Command::new("ssh-key-dir")
        .version(crate_version!())
        .about("Print SSH keys from a user's ~/.ssh/authorized_keys.d")
        .arg(
            Arg::new("user")
                .help("Username of the account to query")
                .value_parser(value_parser!(OsString))
                .default_value(current_user),
        )
}

fn parse_args() -> Result<Config> {
    let current_user = get_current_username().unwrap_or_else(|| OsString::from(""));
    let matches = make_clap(current_user).get_matches();

    Ok(Config {
        username: matches
            .get_one::<OsString>("user")
            .cloned()
            .expect("username missing"),
    })
}

fn switch_user(username: &OsStr) -> Result<(User, SwitchUserGuard)> {
    let user = get_user_by_name(username).with_context(|| format!("no such user {username:?}"))?;
    let guard =
        switch_user_group(user.uid(), user.primary_group_id()).context("couldn't switch user")?;
    Ok((user, guard))
}

fn main() -> Result<()> {
    // parse args
    let opts = parse_args()?;

    // switch user
    let (user, switch_guard) = switch_user(&opts.username)?;

    // read keys
    let key_dir = user.home_dir().join(".ssh");
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let stderr = io::stderr();
    let mut err = stderr.lock();
    read_keys(&key_dir, &mut out, &mut err)?;

    // switch back
    drop(switch_guard);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use uzers::{get_current_username, get_effective_uid};

    fn wrap_switch_user(username: &str) -> Result<User> {
        switch_user(&OsString::from(username)).map(|(u, _g)| u)
    }

    #[test]
    fn test_switch_user() {
        if get_effective_uid() == 0 {
            panic!("can't run tests as root");
        }
        assert_eq!(
            wrap_switch_user("not-a-real-username")
                .unwrap_err()
                .to_string(),
            "no such user \"not-a-real-username\""
        );
        assert_eq!(
            wrap_switch_user("root").unwrap_err().to_string(),
            "couldn't switch user"
        );
        wrap_switch_user(&get_current_username().unwrap().into_string().unwrap()).unwrap();
    }

    #[test]
    fn clap_tests() {
        make_clap(OsString::from("test")).debug_assert();
    }
}
