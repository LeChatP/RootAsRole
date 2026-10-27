use log::{debug, warn};
use serde_json::Value;

use crate::{
    error::{SrError, SrResult},
    finder::de::{DLinkedRole, DRoleFinder},
};

use super::{Api, ApiEvent};

/// Whether the user holds `role`: as one of its actors, or through a role that it holds as an
/// actor and that names `role` in its parents, whose tasks the hierarchy plugin grants.
fn holds(role: &DLinkedRole) -> bool {
    if role.role().user_min.matching() {
        return true;
    }
    #[cfg(feature = "hierarchy")]
    {
        let name = role.role().role.as_ref();
        role.config().roles().any(|senior| {
            senior.role().user_min.matching() && parents(senior.role()).any(|parent| parent == name)
        })
    }
    #[cfg(not(feature = "hierarchy"))]
    false
}

/// The parents that `role` names, one or a list.
#[cfg(feature = "hierarchy")]
fn parents<'r>(role: &'r DRoleFinder<'_>) -> impl Iterator<Item = &'r str> {
    let parents: &[Value] = match role.extra_values.get("parents") {
        Some(Value::Array(parents)) => parents,
        Some(parent @ Value::String(_)) => std::slice::from_ref(parent),
        _ => &[],
    };
    parents.iter().filter_map(Value::as_str)
}

/// The roles that `role` names in its `ssd`, one or a list; another value is a configuration
/// error.
fn named<'r>(role: &'r DRoleFinder<'_>) -> SrResult<Vec<&'r str>> {
    match role.extra_values.get("ssd") {
        None => Ok(Vec::new()),
        Some(Value::String(name)) => Ok(vec![name.as_str()]),
        Some(Value::Array(names)) => Ok(names.iter().filter_map(Value::as_str).collect()),
        Some(value) => {
            debug!("Invalid SSD value: {value:?}");
            Err(SrError::ConfigurationError)
        }
    }
}

/// Whether the separation of duty excludes `role` for the user: the user holds a role that is
/// in conflict with it, even through the hierarchy. A conflict holds both ways, whichever of the
/// two roles names the other in `ssd`, and only between the two roles that it names: a user who
/// holds two conflicting roles can use neither of them.
pub(super) fn excludes(role: &DLinkedRole) -> SrResult<bool> {
    let name = role.role().role.as_ref();
    let own = named(role.role())?;
    // the roles that name this one; an invalid value of theirs is reported when they are used
    let naming: Vec<DLinkedRole> = role
        .config()
        .roles()
        .filter(|other| named(other.role()).is_ok_and(|names| names.contains(&name)))
        .collect();
    // a failed lookup of an actor leaves unknown whether the user holds a role: the separation
    // of duties cannot be checked, so every role of the policy file that takes part in one is
    // disabled (decided by the maintainer on 2026-10-23); SSD only names roles of the same file
    if (role.role().extra_values.contains_key("ssd") || !naming.is_empty())
        && role
            .config()
            .roles()
            .any(|other| other.role().lookup_failed)
    {
        warn!(
            "The role {name} is disabled: it takes part in a separation of duties, and an actor of its policy could not be looked up"
        );
        return Ok(true);
    }
    let conflict = own
        .into_iter()
        .filter_map(|other| role.config().role(other))
        .chain(naming)
        .find(holds);
    if let Some(other) = conflict {
        debug!(
            "The role {name} is excluded: the user also holds {}, in conflict with it",
            other.role().role
        );
        return Ok(true);
    }
    Ok(false)
}

fn check_ssd(event: &mut ApiEvent) -> SrResult<()> {
    if let ApiEvent::ActorMatching(role, _settings, matching) = event
        && role.role().user_min.matching()
        && excludes(role)?
    {
        **matching = false;
    }
    Ok(())
}

pub fn register() {
    Api::register(super::EventKey::ActorMatching, check_ssd);
}
