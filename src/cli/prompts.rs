use bip39::Mnemonic;
use dg_xch_core::blockchain::sized_bytes::{prep_hex_str, Bytes32};
use dg_xch_keys::parse_payout_address;
use dialoguer::theme::ColorfulTheme;
use dialoguer::Input;
use hex::decode;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

pub fn prompt_for_plot_directories() -> Result<Vec<String>, Error> {
    let mut dirs = HashSet::new();
    let mut first = true;
    while let Some(dir) = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt(if first {
            first = false;
            "Enter a Root Plot Directory or leave blank to continue: "
        } else {
            "Enter Another Plot Directory or leave blank to continue: "
        })
        .allow_empty(true)
        .interact_text()
        .map(|input| {
            if input.trim().is_empty() {
                None
            } else {
                Some(input)
            }
        })
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to read user Input for Plot Directory: {e:?}"),
            )
        })?
    {
        let tripmmed = dir.trim();
        let stripped = tripmmed.strip_suffix('/').unwrap_or(tripmmed);
        dirs.insert(stripped.to_string());
    }
    Ok(dirs.into_iter().collect())
}

pub fn prompt_for_payout_address(current: Option<String>) -> Result<Bytes32, Error> {
    let prompt = if let Some(current) = &current {
        format!("Please Input XCH Payout Address, or leave blank to use {current}: ")
    } else {
        String::from("Please Input Your XCH Payout Address: ")
    };
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .allow_empty(true)
        .validate_with(|input: &String| -> Result<(), &str> {
            if (input.trim().is_empty() && current.is_some()) || parse_payout_address(input).is_ok()
            {
                Ok(())
            } else {
                Err("You did not input a valid XCH Address, Please try again.")
            }
        })
        .interact_text()
        .map(|input| {
            if input.trim().is_empty() && current.is_some() {
                current
                    .map(|v| {
                        Bytes32::from(
                            parse_payout_address(&v)
                                .unwrap_or_else(|_| panic!("{input} Not a valid Payout Address")),
                        )
                    })
                    .expect("Just Checked Is Some")
            } else {
                Bytes32::from(parse_payout_address(&input).expect("Checked In Validator"))
            }
        })
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to read user Input for XCH Address: {e:?}"),
            )
        })
}

pub fn prompt_for_launcher_id(current: Option<Bytes32>) -> Result<Option<Bytes32>, Error> {
    let prompt = if let Some(current) = &current {
        format!("Please Input PlotNft LauncherId, leave blank to scan, current {current}: ")
    } else {
        String::from("Please Input PlotNft LauncherId, leave blank to scan: ")
    };
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .allow_empty(true)
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.trim().is_empty()
                || (input.len() == 66 || input.len() == 64 && decode(prep_hex_str(input)).is_ok())
            {
                Ok(())
            } else {
                Err("You did not input a valid LauncherId, Please try again.")
            }
        })
        .interact_text()
        .map(|input| {
            if input.trim().is_empty() {
                current
            } else {
                Some(Bytes32::from(input))
            }
        })
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to read user Input for LauncherId: {e:?}"),
            )
        })
}

pub fn prompt_for_farming_fullnode(current: Option<String>) -> Result<String, Error> {
    let prompt = if let Some(current) = &current {
        format!("Please select Node for Farming, \"community\" or a custom IP/Domain, leave blank to continue Using {current}: ")
    } else {
        String::from("Please select Node for Farming, \"community\" or a custom IP/Domain:")
    };
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .allow_empty(true)
        .validate_with(|input: &String| -> Result<(), &str> {
            let input = input.to_ascii_lowercase();
            let trimmed = input.trim();
            if trimmed.is_empty()
                || ["community", "c"].contains(&trimmed) //Community Node
                || is_domain(trimmed)
                || IpAddr::from_str(trimmed).is_ok()
                || trimmed == "localhost" || trimmed == "l"
            {
                Ok(())
            } else {
                Err("Please Enter community (c) or local (l)")
            }
        })
        .interact_text()
        .map(|input| {
            if input.trim().is_empty() {
                if let Some(current) = current {
                    current
                } else {
                    String::from("localhost")
                }
            } else if ["l", "localhost"].contains(&input.as_str()) {
                String::from("localhost")
            } else if ["c", "community"].contains(&input.as_str()) {
                String::from("chia-proxy.evergreenminer-prod.com")
            } else {
                input.trim().to_string()
            }
        })
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to read user Input for Farming FullNode URL: {e:?}"),
            )
        })
}

pub fn prompt_for_rpc_fullnode(current: Option<String>) -> Result<String, Error> {
    let prompt = if let Some(current) = &current {
        format!("Please Select Your Node for RPC Calls (community/local), leave blank to continue Using {current}: ")
    } else {
        String::from("Please Select Your Node for RPC Calls (community/local): ")
    };
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .allow_empty(true)
        .validate_with(|input: &String| -> Result<(), &str> {
            let input = input.to_ascii_lowercase();
            let trimmed = input.trim();
            if trimmed.is_empty()
                || ["community", "c"].contains(&trimmed) //Community Node
                || is_domain(trimmed)
                || IpAddr::from_str(trimmed).is_ok()
                || trimmed == "localhost" || trimmed == "l"
            {
                Ok(())
            } else {
                Err("Please Enter community (c) or local (l)")
            }
        })
        .interact_text()
        .map(|input| {
            if input.trim().is_empty() {
                if let Some(current) = current {
                    current
                } else {
                    String::from("localhost")
                }
            } else if ["l", "localhost"].contains(&input.as_str()) {
                String::from("localhost")
            } else if ["c", "community"].contains(&input.as_str()) {
                String::from("chia-proxy.evergreenminer-prod.com")
            } else {
                input.trim().to_string()
            }
        })
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to read user Input for FullNode URL: {e:?}"),
            )
        })
}

pub fn prompt_for_farming_port(current: Option<u16>) -> Result<u16, Error> {
    let prompt = if let Some(current) = current {
        format!("Please Input Your Node Farming Port, leave blank to continue Using {current}: ")
    } else {
        String::from("Please Input Your Node Farming Port (Usually 8444 or 443): ")
    };
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .allow_empty(true)
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.trim().is_empty() && current.is_some() {
                Ok(())
            } else {
                u16::from_str(input)
                    .map(|_| ())
                    .map_err(|_| "Input is not a valid u16")
            }
        })
        .interact_text()
        .map(|input| {
            if !input.trim().is_empty() {
                u16::from_str(&input).expect("Was Validated in the validate_with call")
            } else if let Some(current) = current {
                current
            } else {
                0 //Should Never Hit This
            }
        })
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to read user Input for FullNode Farming Port: {e:?}"),
            )
        })
}

pub fn prompt_for_rpc_port(current: Option<u16>) -> Result<u16, Error> {
    let prompt = if let Some(current) = current {
        format!("Please Input Your Node RPC Port, leave blank to continue Using {current}: ")
    } else {
        String::from("Please Input Your Node RPC Port (Usually 8555 or 443): ")
    };
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .allow_empty(true)
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.trim().is_empty() && current.is_some() {
                Ok(())
            } else {
                u16::from_str(input)
                    .map(|_| ())
                    .map_err(|_| "Input is not a valid u16")
            }
        })
        .interact_text()
        .map(|input| {
            if !input.trim().is_empty() {
                u16::from_str(&input).expect("Was Validated in the validate_with call")
            } else if let Some(current) = current {
                current
            } else {
                0 //Should Never Hit This
            }
        })
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to read user Input for FullNode RPC Port: {e:?}"),
            )
        })
}

pub fn prompt_for_ssl_path(current: Option<String>) -> Result<Option<String>, Error> {
    let prompt = if let Some(current) = &current {
        format!("Input Node SSL Path for custom certs or hit enter, currently using {current}: ")
    } else {
        String::from("Input Node SSL Path for custom certs or hit enter: ")
    };
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .allow_empty(true)
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.is_empty() {
                Ok(())
            } else {
                let path = Path::new(input);
                if path.exists() {
                    Ok(())
                } else {
                    Err("Input is not a valid directory")
                }
            }
        })
        .interact_text()
        .map(|input| {
            if input.is_empty() {
                current
            } else {
                Some(input)
            }
        })
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to read user Input for SSL Path: {e:?}"),
            )
        })
}

pub fn prompt_for_mnemonic<P: AsRef<Path>>(path: Option<P>) -> Result<Mnemonic, Error> {
    if let Some(mnemonic_file) = path {
        Mnemonic::from_str(
            &fs::read_to_string(mnemonic_file)
                .map_err(|e| Error::new(e.kind(), format!("Failed to Mnemonic File: {e:?}")))?,
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to parse Mnemonic: {e:?}"),
            )
        })
    } else {
        Mnemonic::from_str(
            &Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("Please Input Your Mnemonic: ")
                .validate_with(|input: &String| -> Result<(), &str> {
                    if Mnemonic::from_str(input).is_ok() {
                        Ok(())
                    } else {
                        Err("You did not input a valid Mnemonic, Please try again.")
                    }
                })
                .interact_text()
                .map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("Failed to read user Input for Mnemonic: {e:?}"),
                    )
                })?,
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to parse Mnemonic: {e:?}"),
            )
        })
    }
}

static DOMAIN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:[a-zA-Z0-9-]{0,63}\.)*[a-zA-Z0-9-]{1,63}\.[a-zA-Z]{2,63}$")
        .expect("Invalid regular expression")
});

fn is_domain(domain: &str) -> bool {
    DOMAIN_REGEX.is_match(domain)
}
