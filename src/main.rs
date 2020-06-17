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

use clap::{crate_version, App, AppSettings, Arg};
use error_chain::quick_main;
use users::os::unix::UserExt;
use users::switch::{switch_user_group, SwitchUserGuard};
use users::{get_current_username, get_user_by_name, User};

use crate::errors::{Result, ResultExt};
use crate::keys::read_keys;

mod errors;
mod keys;

quick_main!(run);

struct Config {
    username: OsString,
}

fn parse_args() -> Result<Config> {
    let current_user = get_current_username().unwrap_or_else(|| OsString::from(""));

    // Args are listed in --help in the order declared here.  Please keep
    // the entire help text to 80 columns.
    let matches = App::new("ssh-key-dir")
        .version(crate_version!())
        .global_setting(AppSettings::UnifiedHelpMessage)
        .about("Print SSH keys from a user's ~/.ssh/authorized_keys.d")
        .arg(
            Arg::with_name("user")
                .help("Username of the account to query")
                .takes_value(true)
                .default_value_os(&current_user),
        )
        .get_matches();

    Ok(Config {
        username: matches
            .value_of_os("user")
            .map(OsString::from)
            .expect("username missing"),
    })
}

fn switch_user(username: &OsStr) -> Result<(User, SwitchUserGuard)> {
    let user = get_user_by_name(username).chain_err(|| format!("no such user {:?}", username))?;
    let guard = switch_user_group(user.uid(), user.primary_group_id())
        .chain_err(|| "couldn't switch user")?;
    Ok((user, guard))
}

fn run() -> Result<()> {
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

    use users::{get_current_username, get_effective_uid};

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
        assert_eq!(
            wrap_switch_user(&get_current_username().unwrap().into_string().unwrap())
                .map(|_u| ())
                .unwrap(),
            ()
        );
    }
}
