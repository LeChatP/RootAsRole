//extern crate sudoers_reader;

mod capabilities;
mod checklist;
mod cli;
mod config;
mod options;
mod rolemanager;
mod state;
mod version;
mod util;

use crate::config::FILENAME;
use cli::parse_args;
use cursive::Cursive;
use rolemanager::RoleContext;
use state::{role::SelectRoleState, InitState};
use tracing_subscriber::FmtSubscriber;

pub enum ActorType {
    User,
    Group,
}

pub struct RoleManagerApp {
    manager: RoleContext,
    state: Box<dyn state::State>,
}

fn main() {
    let roles = config::load::load_roles(FILENAME);
    if let Err(err) = roles {
        eprintln!("{}", err.to_string());
        std::process::exit(1);
    }
    let roles = roles.unwrap();
    let mut rc_role_manager = RoleContext::new(roles);
    match parse_args(&mut rc_role_manager) {
        Ok(value) => {
            if value {
                std::process::exit(0);
            }
        }
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    }
    // a builder for `FmtSubscriber`.
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(tracing::Level::TRACE)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let mut siv = cursive::default();
    //let caps = rc_role_manager.as_ref().borrow().selected_command_group().as_ref().borrow().get_capabilities();
    //siv.add_layer(select_capabilities(rc_role_manager.to_owned(), caps.into()));

    siv.add_layer(SelectRoleState.init(&mut rc_role_manager));
    SelectRoleState.config_cursive(&mut siv);

    let app = RoleManagerApp {
        manager: rc_role_manager,
        state: Box::new(SelectRoleState),
    };

    siv.set_user_data(app);
    siv.run();
}
