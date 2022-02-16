pub mod crypt;
pub mod definitions;
pub mod donut;
pub mod loader;
pub mod utils;

use definitions::{DonutConfig, DonutParser};
use donut::{create_config, donut_from_file};
use std::{
    fs,
    io::prelude::*,
};

fn main() {
    // parse args
    let cli: DonutParser = argh::from_env();

    // create config
    let mut config = DonutConfig::default();
    create_config(&cli, &mut config);

    // create donut payload
    let payload = match donut_from_file(cli.input, &mut config) {
        Ok(payload) => payload,
        Err(e) => {
            println!("{}", e);
            std::process::exit(1);
        },
    };

    // write payload to file
    let mut output_file = fs::File::create(cli.output).expect("could not write file");
    output_file
        .write_all(&payload)
        .expect("could not write contents to output file");
}

