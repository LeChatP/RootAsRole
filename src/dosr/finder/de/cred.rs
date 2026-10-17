use std::{borrow::Cow, collections::HashMap};

use bon::Builder;
use capctl::CapSet;
use log::debug;
use nix::unistd::{Group, User};
use rootasrole_core::{
    database::{
        actor::{DGroupType, DGroups, DUserType},
        score::{CapsMin, SetgidMin, SetuidMin, TaskScore},
        structs::{SCapabilities, SetBehavior},
    },
    util::capabilities_are_exploitable,
};
use serde::{
    Deserialize,
    de::{DeserializeSeed, IgnoredAny},
};
use serde_json::Value;

use crate::Cli;

pub(super) struct CredFinderDeserializerReturn<'a> {
    pub(super) cli: &'a Cli,
}

#[derive(Debug, PartialEq, Eq, Default, Builder)]
pub struct CredData<'a> {
    pub setuid: Option<DUserType<'a>>,
    pub setgroups: Option<DGroups<'a>>,
    pub caps: Option<CapSet>,
    #[builder(default)]
    pub extra_values: HashMap<Cow<'a, str>, Value>,
}

#[derive(Debug, PartialEq, Eq, Default, Clone, Builder)]
pub struct CredOwnedData {
    pub setuid: Option<User>,
    pub setgroups: Option<Vec<Group>>,
    pub caps: Option<CapSet>,
    #[builder(default)]
    pub extra_values: HashMap<String, Value>,
}

#[derive(Debug)]
pub(super) struct CredResult<'a> {
    pub(super) cred: CredData<'a>,
    pub(super) score: TaskScore,
    pub(super) ok: bool,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for CredFinderDeserializerReturn<'a> {
    type Value = CredResult<'a>;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field<'a> {
            #[serde(alias = "u")]
            Setuid,
            #[serde(alias = "g", alias = "setgroups")]
            Setgid,
            #[serde(alias = "c", alias = "capabilities")]
            Caps,
            #[serde(untagged, borrow)]
            Other(Cow<'a, str>),
        }

        struct CredFinderVisitor<'a> {
            cli: &'a Cli,
        }

        fn get_caps_min(caps: CapSet) -> CapsMin {
            if caps.is_empty() {
                CapsMin::NoCaps
            } else if caps == !CapSet::empty() {
                CapsMin::CapsAll
            } else if capabilities_are_exploitable(caps) {
                CapsMin::CapsAdmin(caps.size())
            } else {
                CapsMin::CapsNoAdmin(caps.size())
            }
        }

        impl<'de: 'a, 'a> serde::de::Visitor<'de> for CredFinderVisitor<'a> {
            type Value = CredResult<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("Cred structure")
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut setuid = None;
                let mut setgroups = None;
                let mut caps = None;
                let mut score = TaskScore::default();
                let mut ok = true;
                let mut extra_values = HashMap::new();
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Setuid => {
                            debug!("CredFinderVisitor: setuid");
                            let (user, setuser_min, user_ok) =
                                map.next_value_seed(SetUserDeserializerReturn { cli: self.cli })?;
                            setuid = user;
                            score.setuser_min.uid = setuser_min;
                            if !user_ok {
                                ok = false;
                            }
                        }
                        Field::Setgid => {
                            debug!("CredFinderVisitor: setgid");
                            let (groups, setuser_min, groups_ok) =
                                map.next_value_seed(SetGroupsDeserializerReturn { cli: self.cli })?;
                            setgroups = groups;
                            score.setuser_min.gid = setuser_min;
                            if !groups_ok {
                                ok = false;
                            }
                        }
                        Field::Caps => {
                            debug!("CredFinderVisitor: capabilities");
                            let scaps: SCapabilities = map.next_value()?;
                            let capset = scaps.to_capset();
                            score.caps_min = get_caps_min(capset);
                            caps = Some(capset);
                        }
                        Field::Other(n) => {
                            debug!("CredFinderVisitor: unknown {n}");
                            let v: Value = map.next_value()?;
                            extra_values.insert(n, v);
                        }
                    }
                }
                debug!("CredFinderVisitor: end");
                Ok(CredResult {
                    cred: CredData {
                        setuid,
                        setgroups,
                        caps,
                        extra_values,
                    },
                    score,
                    ok,
                })
            }
        }
        const FIELDS: &[&str] = &["setuid", "setgroups", "capabilities", "0", "1", "2"];
        deserializer.deserialize_struct("Cred", FIELDS, CredFinderVisitor { cli: self.cli })
    }
}

/// Fixed groups of the policy (a group or a list of groups): `-g` can only ask for the same list,
/// in the same order, since the first group is the primary group.
fn fixed_groups<'a, E: serde::de::Error>(
    cli: &Cli,
    groups: DGroups<'a>,
) -> Result<(Option<DGroups<'a>>, Option<SetgidMin>, bool), E> {
    if let Some(requested) = cli.opt_filter.as_ref().and_then(|f| f.group.as_ref()) {
        let ids: Vec<u32> = (&groups).try_into().map_err(E::custom)?;
        if *requested != ids {
            return Ok((None, None, false));
        }
    }
    let score = Some(SetgidMin::from(&groups));
    Ok((Some(groups), score, true))
}

// New deserializer for SetGroups that returns values instead of using &mut
struct SetGroupsDeserializerReturn<'a> {
    cli: &'a Cli,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for SetGroupsDeserializerReturn<'a> {
    type Value = (Option<DGroups<'a>>, Option<SetgidMin>, bool);
    #[allow(clippy::too_many_lines)]
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field {
            #[serde(alias = "d")]
            Default,
            #[serde(alias = "f")]
            Fallback,
            #[serde(alias = "a")]
            Add,
            #[serde(alias = "s", alias = "sub")]
            Del,
        }
        struct SGroupsChooserVisitor<'a> {
            cli: &'a Cli,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for SGroupsChooserVisitor<'a> {
            type Value = (Option<DGroups<'a>>, Option<SetgidMin>, bool);

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("SGroups structure")
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SGroupsChooserVisitor: visit_borrowed_str");
                let group: DGroupType<'_> = v
                    .parse::<u32>()
                    .map_or_else(|_| v.into(), std::convert::Into::into);
                fixed_groups(self.cli, DGroups::Single(group))
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SGroupsChooserVisitor: visit_str");
                self.visit_string(v.to_string())
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SGroupsChooserVisitor: visit_string");
                let group: DGroupType<'_> = v
                    .parse::<u32>()
                    .map_or_else(|_| Cow::<str>::from(v).into(), std::convert::Into::into);
                fixed_groups(self.cli, DGroups::Single(group))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SGroupsChooserVisitor: visit_u64");
                let group: DGroupType<'_> = <DGroupType<'_>>::from(
                    u32::try_from(v).map_err(|_| serde::de::Error::custom("Group id too large"))?,
                );
                fixed_groups(self.cli, DGroups::Single(group))
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                debug!("SGroupsChooserVisitor: visit_seq");
                // a list is one set of groups, the first one is the primary group
                let mut groups = Vec::new();
                while let Some(group) = seq.next_element::<DGroups>()? {
                    match group {
                        DGroups::Single(group) => groups.push(group),
                        // like rootasrole-core: several sets of groups need the selector form
                        DGroups::Multiple(_) => {
                            return Err(serde::de::Error::custom(
                                "a list of groups cannot contain lists, use the add list of a selector",
                            ));
                        }
                    }
                }
                if groups.is_empty() {
                    return Ok((None, None, false));
                }
                fixed_groups(self.cli, DGroups::from(groups))
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut groups = None;
                let mut score = None;
                let mut ok = false;
                let mut default_all = false;
                let filter = self.cli.opt_filter.as_ref().and_then(|x| x.group.as_ref());
                'fields: while let Some(key) = map.next_key()? {
                    match key {
                        Field::Default => {
                            debug!("SGroupsChooserVisitor: default");
                            let default = map.next_value::<SetBehavior>()?;
                            if default.is_all() {
                                ok = true;
                                default_all = true;
                            }
                        }
                        Field::Fallback => {
                            debug!("SGroupsChooserVisitor: fallback");
                            let value = map.next_value::<DGroups>()?;
                            if let Some(u) = filter {
                                let parsed_ids: Vec<u32> =
                                    (&value).try_into().map_err(serde::de::Error::custom)?;
                                if *u == parsed_ids {
                                    ok = true;
                                    groups = Some(value.clone());
                                    score.replace((&value).into());
                                }
                            } else {
                                groups = Some(value.clone());
                                ok = true;
                                score.replace((&value).into());
                            }
                        }
                        Field::Add => {
                            debug!("SGroupsChooserVisitor: add");
                            if let Some(filter) = filter {
                                let add = map.next_value::<Cow<'_, [DGroups]>>()?;
                                for group in add.iter() {
                                    let v: Vec<u32> =
                                        group.try_into().map_err(serde::de::Error::custom)?;
                                    if v == *filter {
                                        // the next fields are still read: a del entry wins
                                        ok = true;
                                        groups = Some(group.to_owned());
                                        score.replace(group.into());
                                        break;
                                    }
                                }
                            } else {
                                map.next_value::<IgnoredAny>()?;
                            }
                        }
                        Field::Del => {
                            debug!("SGroupsChooserVisitor: del");
                            if let Some(u) = filter {
                                for group in map.next_value::<Cow<'_, [DGroups]>>()?.iter() {
                                    if let Ok(v) = TryInto::<Vec<u32>>::try_into(group) {
                                        if v == *u {
                                            while map
                                                .next_entry::<IgnoredAny, IgnoredAny>()?
                                                .is_some()
                                            {
                                            }
                                            ok = false;
                                            groups = None;
                                            score = None;
                                            break 'fields;
                                        }
                                    } else {
                                        return Err(serde::de::Error::custom("Invalid group"));
                                    }
                                }
                            } else {
                                map.next_value::<IgnoredAny>()?;
                            }
                        }
                    }
                }
                // allowed by `"default": "all"` without being listed: the requested groups
                if ok
                    && groups.is_none()
                    && default_all
                    && let Some(requested) = filter
                {
                    let requested = match requested.as_slice() {
                        [gid] => DGroups::Single(DGroupType::from(*gid)),
                        gids => {
                            DGroups::Multiple(gids.iter().copied().map(DGroupType::from).collect())
                        }
                    };
                    score.replace((&requested).into());
                    groups = Some(requested);
                }
                Ok((groups, score, ok))
            }
        }
        deserializer.deserialize_any(SGroupsChooserVisitor { cli: self.cli })
    }
}

// New deserializer for SetUser that returns values instead of using &mut
struct SetUserDeserializerReturn<'a> {
    cli: &'a Cli,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for SetUserDeserializerReturn<'a> {
    type Value = (Option<DUserType<'a>>, Option<SetuidMin>, bool);
    #[allow(clippy::too_many_lines)]
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field {
            #[serde(alias = "d")]
            Default,
            #[serde(alias = "f")]
            Fallback,
            #[serde(alias = "a")]
            Add,
            #[serde(alias = "s", alias = "sub")]
            Del,
        }
        struct SetUserVisitor<'a> {
            cli: &'a Cli,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for SetUserVisitor<'a> {
            type Value = (Option<DUserType<'a>>, Option<SetuidMin>, bool);
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("SUser structure")
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SetUserVisitor: visit_borrowed_str");
                let user = v
                    .parse::<u32>()
                    .map_or_else(|_| DUserType::from(v), DUserType::from);
                let score = Some(SetuidMin::from(&user));
                let ok = true;
                if let Some(y) = &self.cli.opt_filter.as_ref().and_then(|x| x.user)
                    && *y
                        != user
                            .fetch_id()
                            .ok_or_else(|| serde::de::Error::custom("User does not exist"))?
                {
                    return Ok((None, None, false));
                }
                Ok((Some(user), score, ok))
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SetUserVisitor: visit_str");
                self.visit_string(v.to_string())
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SetUserVisitor: visit_string");
                let user = v
                    .parse::<u32>()
                    .map_or_else(|_| DUserType::from(v), DUserType::from);
                let score = Some(SetuidMin::from(&user));
                let ok = true;
                if let Some(y) = &self.cli.opt_filter.as_ref().and_then(|x| x.user)
                    && *y
                        != user
                            .fetch_id()
                            .ok_or_else(|| serde::de::Error::custom("User does not exist"))?
                {
                    return Ok((None, None, false));
                }
                Ok((Some(user), score, ok))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SetUserVisitor: visit_i64");
                let user = DUserType::from(
                    u32::try_from(v).map_err(|_| serde::de::Error::custom("User id too large"))?,
                );
                let score = Some(SetuidMin::from(&user));
                let ok = true;
                if let Some(y) = &self.cli.opt_filter.as_ref().and_then(|x| x.user)
                    && *y
                        != user
                            .fetch_id()
                            .ok_or_else(|| serde::de::Error::custom("User does not exist"))?
                {
                    return Ok((None, None, false));
                }
                Ok((Some(user), score, ok))
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut user = None;
                let mut score = None;
                let mut ok = false;
                let mut default_all = false;
                let filter = self.cli.opt_filter.as_ref().and_then(|x| x.user.as_ref());
                'fields: while let Some(key) = map.next_key()? {
                    match key {
                        Field::Default => {
                            debug!("SUserChooserVisitor: default");
                            let default = map.next_value::<SetBehavior>()?;
                            if default.is_all() {
                                ok = true;
                                default_all = true;
                            }
                        }
                        Field::Fallback => {
                            debug!("SUserChooserVisitor: fallback");
                            let value = map.next_value::<DUserType>()?;
                            if let Some(u) = filter {
                                let userid = value.fetch_id().ok_or_else(|| {
                                    serde::de::Error::custom("User does not exist")
                                })?;
                                if u == &userid {
                                    score.replace((&value).into());
                                    user = Some(value);
                                    ok = true;
                                }
                            } else {
                                ok = true;
                                score.replace((&value).into());
                                user = Some(value);
                            }
                        }
                        Field::Add => {
                            debug!("SUserChooserVisitor: add");
                            if let Some(filter) = filter {
                                let users = map.next_value::<Cow<'_, [DUserType]>>()?;
                                for user_item in users.iter() {
                                    let user_id = user_item.fetch_id().ok_or_else(|| {
                                        serde::de::Error::custom("User does not exist")
                                    })?;
                                    if user_id == *filter {
                                        ok = true;
                                        user = Some(user_item.to_owned());
                                        score.replace(user_item.into());
                                        break;
                                    }
                                }
                            } else {
                                map.next_value::<IgnoredAny>()?;
                            }
                        }
                        Field::Del => {
                            debug!("SUserChooserVisitor: del");
                            if let Some(u) = filter {
                                let users = map.next_value::<Cow<'_, [DUserType]>>()?;
                                for user_item in users.iter() {
                                    let user_id = user_item.fetch_id().ok_or_else(|| {
                                        serde::de::Error::custom("User does not exist")
                                    })?;
                                    if user_id == *u {
                                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some()
                                        {
                                        }
                                        score = None;
                                        user = None;
                                        ok = false;
                                        break 'fields;
                                    }
                                }
                            } else {
                                map.next_value::<IgnoredAny>()?;
                            }
                        }
                    }
                }
                // allowed by `"default": "all"` without being listed: the requested user
                if ok
                    && user.is_none()
                    && default_all
                    && let Some(uid) = filter
                {
                    let requested = DUserType::from(*uid);
                    score.replace((&requested).into());
                    user = Some(requested);
                }
                Ok((user, score, ok))
            }
        }
        deserializer.deserialize_any(SetUserVisitor { cli: self.cli })
    }
}

#[cfg(test)]
mod test {

    use crate::finder::de::tests::{get_non_root_gid, get_non_root_uid};

    use super::*;
    use capctl::Cap;
    use rootasrole_core::database::{
        FilterMatcher,
        actor::{DGroupType, SGroupType},
        score::{SetgidMin, SetuidMin},
    };
    use test_log::test;

    #[test]
    fn test_setuserdeserializerreturn() {
        let json =
            r#"{"default": "none", "fallback": "user1", "add": ["user2"], "del": ["user3"]}"#;
        let cli = Cli::builder().build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(ok);
        let user1 = DUserType::from("user1");
        assert_eq!(score, Some(SetuidMin::from(&user1)));
        assert_eq!(user, Some(user1));
    }

    #[test]
    fn test_setuserdeserializerreturn_filter() {
        let uid1 = get_non_root_uid(0).unwrap();
        let uid2 = get_non_root_uid(1).unwrap();
        let json = format!(
            r#"{{"default": "none", "fallback": "root", "add": [{uid1}], "del": [{uid2}]}}"#
        );
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user(uid1).unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(ok);
        let user1 = DUserType::from(uid1);
        assert_eq!(score, Some(SetuidMin::from(&user1)));
        assert_eq!(user, Some(user1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user("root").unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(ok);
        let user1 = DUserType::from("root");
        assert_eq!(score, Some(SetuidMin::from(&user1)));
        assert_eq!(user, Some(user1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user(uid2).unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(user, None);
        let json = "\"root\"";
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user("root").unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let (user, score, ok) = result.unwrap();
        assert!(ok);
        let user1 = DUserType::from("root");
        assert_eq!(score, Some(SetuidMin::from(&user1)));
        assert_eq!(user, Some(user1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user(uid1).unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(user, None);
        let json = "0";
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user(uid1).unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(user, None);
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user("root").unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(ok);
        let user1 = DUserType::from(0);
        assert_eq!(score, Some(SetuidMin::from(&user1)));
        assert_eq!(user, Some(user1));
    }

    #[test]
    fn test_no_fallback() {
        let json = r#"{"default": "all"}"#;
        let cli = Cli::builder().build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(ok);
        assert_eq!(score, None);
        assert_eq!(user, None);
    }

    #[test]
    fn test_setgroupsdeserializerreturn() {
        let json = r#"{"default": "none", "fallback": [1, 2], "add": [[3, 4]], "del": [[5, 6]]}"#;
        let cli = Cli::builder().build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::from(vec![1.into(), 2.into()]);
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
    }

    /// The uid chosen by the selector `json` for `dosr -u <requested>`, or `None` if refused.
    fn chosen_user(json: &str, requested: Option<u32>) -> Option<(Option<u32>, SetuidMin)> {
        let filter = requested.map(|uid| FilterMatcher::builder().user(uid).unwrap().build());
        let cli = Cli::builder().maybe_opt_filter(filter).build();
        let (user, score, ok) = SetUserDeserializerReturn { cli: &cli }
            .deserialize(&mut serde_json::Deserializer::from_str(json))
            .unwrap();
        ok.then(|| (user.and_then(|user| user.fetch_id()), score.unwrap()))
    }

    #[test]
    fn test_user_selector_all_applies_the_requested_user() {
        let fallback = get_non_root_uid(0).unwrap();
        let other = get_non_root_uid(1).unwrap();
        let deleted = get_non_root_uid(2).unwrap();
        let json = format!(r#"{{"default": "all", "fallback": {fallback}, "del": [{deleted}]}}"#);
        // a user that the policy does not list runs the command as this user, not as the caller
        let (uid, score) = chosen_user(&json, Some(other)).unwrap();
        assert_eq!(uid, Some(other));
        assert_eq!(score, SetuidMin::from(&DUserType::from(other)));
        // root is scored as root
        let (uid, score) = chosen_user(&json, Some(0)).unwrap();
        assert_eq!(uid, Some(0));
        assert_eq!(score, SetuidMin::from(&DUserType::from(0)));
        assert_ne!(score, SetuidMin::from(&DUserType::from(other)));
        assert!(chosen_user(&json, Some(deleted)).is_none());
        assert_eq!(chosen_user(&json, None).unwrap().0, Some(fallback));
    }

    /// The groups chosen by `json` for `dosr -g <requested>`, or `None` if refused.
    fn chosen_groups(json: &str, requested: Option<&[u32]>) -> Option<(Vec<u32>, SetgidMin)> {
        let filter = requested.map(|gids| {
            let gids: Vec<SGroupType> = gids.iter().map(|gid| (*gid).into()).collect();
            FilterMatcher::builder().group(gids).unwrap().build()
        });
        let cli = Cli::builder().maybe_opt_filter(filter).build();
        let (groups, score, ok) = SetGroupsDeserializerReturn { cli: &cli }
            .deserialize(&mut serde_json::Deserializer::from_str(json))
            .unwrap();
        ok.then(|| ((&groups.unwrap()).try_into().unwrap(), score.unwrap()))
    }

    #[test]
    fn test_group_selector_all_applies_the_requested_groups() {
        let fallback = get_non_root_gid(0).unwrap();
        let other = get_non_root_gid(1).unwrap();
        let deleted = get_non_root_gid(2).unwrap();
        let json =
            format!(r#"{{"default": "all", "fallback": [{fallback}], "del": [[{deleted}]]}}"#);
        let (groups, score) = chosen_groups(&json, Some(&[other, fallback])).unwrap();
        assert_eq!(groups, [other, fallback]);
        assert_eq!(score, SetgidMin::from(&vec![other, fallback]));
        // root is scored as root
        let (groups, score) = chosen_groups(&json, Some(&[0])).unwrap();
        assert_eq!(groups, [0]);
        assert_eq!(score, SetgidMin::from(&vec![0]));
        assert_ne!(score, SetgidMin::from(&vec![other]));
        assert!(chosen_groups(&json, Some(&[deleted])).is_none());
        assert_eq!(chosen_groups(&json, None).unwrap().0, [fallback]);
    }

    #[test]
    fn test_fixed_groups_need_the_same_list() {
        let gid = get_non_root_gid(0).unwrap();
        let list = format!("[0, {gid}]");
        assert_eq!(chosen_groups(&list, None).unwrap().0, [0, gid]);
        assert_eq!(chosen_groups(&list, Some(&[0, gid])).unwrap().0, [0, gid]);
        // a part of the list, or another order (the first group is the primary group)
        assert!(chosen_groups(&list, Some(&[0])).is_none());
        assert!(chosen_groups(&list, Some(&[gid, 0])).is_none());
        // a single group cannot be completed with -g
        assert!(chosen_groups("0", Some(&[0, gid])).is_none());
        assert_eq!(chosen_groups("0", Some(&[0])).unwrap().0, [0]);
    }

    #[test]
    fn test_group_selector_del_wins_over_add() {
        let gid = get_non_root_gid(0).unwrap();
        for json in [
            format!(r#"{{"default": "none", "add": [[{gid}]], "del": [[{gid}]]}}"#),
            format!(r#"{{"default": "none", "del": [[{gid}]], "add": [[{gid}]]}}"#),
        ] {
            assert!(chosen_groups(&json, Some(&[gid])).is_none(), "{json}");
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_setgroupsdeserializerreturn_filter() {
        let gid1 = get_non_root_gid(0).unwrap();
        let gid2 = get_non_root_gid(1).unwrap();
        let json = format!(
            r#"{{"default": "none", "fallback": ["root"], "add": [[{gid1}]], "del": [[{gid2}]]}}"#
        );
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group("root").unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::Single("root".into());
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group(gid1).unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::Single(gid1.into());
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group(gid2).unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(groups, None);
        let json = "\"root\"";
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group("root").unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::Single("root".into());
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group(gid1).unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(groups, None);
        let json = "0";
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group(gid1).unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(groups, None);
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group("root").unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::Single(0.into());
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
        // a list is one set of groups, like in rootasrole-core
        let json = "[\"root\", 1]";
        let cli = Cli::builder()
            .opt_filter(
                FilterMatcher::builder()
                    .group(vec!["root".into(), Into::<SGroupType>::into(1)])
                    .unwrap()
                    .build(),
            )
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::from(vec!["root".into(), 1.into()]);
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::from(vec!["root".into(), 1.into()]);
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group(gid1).unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(groups, None);
        // a list of lists is refused, as rootasrole-core does: several sets need a selector
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result =
            deserializer.deserialize(&mut serde_json::Deserializer::from_str("[[\"root\", 1]]"));
        assert!(result.is_err());
    }

    #[test]
    fn test_no_fallback_groups() {
        let json = r#"{"default": "all"}"#;
        let cli = Cli::builder().build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        assert_eq!(score, None);
        assert_eq!(groups, None);
    }

    #[test]
    fn test_cred_deserializer() {
        let json = r#"{"setuid":"root", "setgid":"root", "caps": ["CAP_SYS_ADMIN"]}"#;
        let cli = Cli::builder().build();
        let deserializer = CredFinderDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let result = result.unwrap();
        assert!(result.ok);
        assert_eq!(result.cred.setuid, Some("root".into()));
        assert_eq!(
            result.cred.setgroups,
            Some(DGroups::from(vec!["root".into()]))
        );
        assert_eq!(
            result.cred.caps,
            Some(CapSet::from_iter(vec![Cap::SYS_ADMIN]))
        );
        assert_eq!(
            result.score.setuser_min.uid,
            Some(SetuidMin::from(&"root".into()))
        );
        assert_eq!(
            result.score.setuser_min.gid,
            Some(SetgidMin::from(&Into::<DGroupType<'_>>::into("root")))
        );
        assert_eq!(result.score.caps_min, CapsMin::CapsAdmin(1));

        let uid = get_non_root_uid(0).unwrap();
        let gid = get_non_root_gid(0).unwrap();
        let json = format!(r#"{{"setuid":{uid}, "setgid":[{gid}]}}"#);
        let cli = Cli::builder().build();
        let deserializer = CredFinderDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let result = result.unwrap();
        assert!(result.ok);
        assert_eq!(result.cred.setuid, Some(uid.into()));
        assert_eq!(result.cred.setgroups, Some(DGroups::from(vec![gid.into()])));
        assert_eq!(result.cred.caps, None);
        assert_eq!(
            result.score.setuser_min.uid,
            Some(SetuidMin::from(&uid.into()))
        );
        assert_eq!(
            result.score.setuser_min.gid,
            Some(SetgidMin::from(&Into::<DGroupType<'_>>::into(uid)))
        );
        assert_eq!(result.score.caps_min, CapsMin::Undefined);

        let uid = get_non_root_uid(0).unwrap();
        let gid = get_non_root_gid(0).unwrap();
        let json = format!(r#"{{"setuid":"{uid}", "setgid":["{gid}"]}}"#);
        let cli = Cli::builder().build();
        let deserializer = CredFinderDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let result = result.unwrap();
        assert!(result.ok);
        assert_eq!(result.cred.setuid, Some(uid.into()));
        assert_eq!(result.cred.setgroups, Some(DGroups::from(vec![gid.into()])));
        assert_eq!(result.cred.caps, None);
        assert_eq!(
            result.score.setuser_min.uid,
            Some(SetuidMin::from(&uid.into()))
        );
        assert_eq!(
            result.score.setuser_min.gid,
            Some(SetgidMin::from(&Into::<DGroupType<'_>>::into(uid)))
        );
        assert_eq!(result.score.caps_min, CapsMin::Undefined);
    }

    #[test]
    fn test_cred_deserializer_invalid() {
        let json = r#"{"setuid":-1, "setgid":"invalid", "caps": ["CAP_SYS_ADMIN"]}"#;
        let cli = Cli::builder().build();
        let deserializer = CredFinderDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_err(), "Expected error, got: {result:?}");
        let json = r#"{"setuid":"invalid", "setgid":-1, "caps": ["CAP_SYS_ADMIN"]}"#;
        let cli = Cli::builder().build();
        let deserializer = CredFinderDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_err(), "Expected error, got: {result:?}");
    }

    #[test]
    fn test_expecting_error() {
        let seq = "[1, 2, 3]";
        let float = "1.0";
        let cli = Cli::builder().build();
        let cred = CredFinderDeserializerReturn { cli: &cli };
        let result = cred.deserialize(&mut serde_json::Deserializer::from_str(seq));
        assert!(result.is_err(), "Expected error, got: {result:?}");
        let setuser = SetUserDeserializerReturn { cli: &cli };
        let result = setuser.deserialize(&mut serde_json::Deserializer::from_str(float));
        assert!(result.is_err(), "Expected error, got: {result:?}");
        let setgroups = SetGroupsDeserializerReturn { cli: &cli };
        let result = setgroups.deserialize(&mut serde_json::Deserializer::from_str(float));
        assert!(result.is_err(), "Expected error, got: {result:?}");
    }
}
