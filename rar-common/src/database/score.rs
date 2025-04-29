use std::cmp::Ordering;

use bon::Builder;
use strum::EnumIs;

use super::actor::{DGroupType, DGroups, DUserType, SGroupType, SGroups, SUserType};


#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug, EnumIs, Default)]
#[repr(u32)]
// Matching user groups for the role
pub enum ActorMatchMin {
    UserMatch,
    GroupMatch(usize),
    #[default]
    NoMatch,
}

impl ActorMatchMin {
    pub fn better(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Less
    }
    pub fn matching(&self) -> bool {
        *self != ActorMatchMin::NoMatch
    }
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug)]

// Matching setuid and setgid for the role
pub struct SetuidMin {
    is_root: bool,
}

impl From<SUserType> for SetuidMin {
    fn from(s: SUserType) -> Self {
        SetuidMin {
            is_root: user_is_root(&s),
        }
    }
}

impl From<&DUserType<'_>> for SetuidMin {
    fn from(s: &DUserType) -> Self {
        SetuidMin {
            is_root: duser_is_root(s),
        }
    }
}

impl From<u32> for SetuidMin {
    fn from(s: u32) -> Self {
        SetuidMin {
            is_root: s == 0,
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct SetgidMin {
    is_root: bool,
    nb_groups: usize,
}

impl From<SGroups> for SetgidMin {
    fn from(s: SGroups) -> Self {
        SetgidMin {
            is_root: groups_contains_root(Some(&s)),
            nb_groups: groups_len(Some(&s)),
        }
    }
}

impl From<&DGroups<'_>> for SetgidMin {
    fn from(s: &DGroups<'_>) -> Self {
        SetgidMin {
            is_root: dgroups_contains_root(Some(s)),
            nb_groups: dgroups_len(Some(&s)),
        }
    }
}

impl From<&DGroupType<'_>> for SetgidMin {
    fn from(s: &DGroupType<'_>) -> Self {
        SetgidMin {
            is_root: dgroup_is_root(&s),
            nb_groups: 1,
        }
    }
}

impl From<&Vec<u32>> for SetgidMin {
    fn from(s: &Vec<u32>) -> Self {
        SetgidMin {
            is_root: s.iter().any(|id| *id == 0),
            nb_groups: s.len(),
        }
    }
}

impl PartialOrd for SetgidMin {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SetgidMin {
    fn cmp(&self, other: &Self) -> Ordering {
        self.is_root
            .cmp(&other.is_root)
            .then_with(|| self.nb_groups.cmp(&other.nb_groups))
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
pub struct SetUserMin {
    pub uid: Option<SetuidMin>,
    pub gid: Option<SetgidMin>,
}
impl PartialOrd for SetUserMin {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SetUserMin {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uid
            .cmp(&other.uid)
            .then_with(|| self.gid.cmp(&other.gid))
    }
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug, Default)]
pub struct CmdMin(u32);

bitflags::bitflags! {

    impl CmdMin: u32 {
        const Match = 0b00001;
        const WildcardPath = 0b00010;
        const RegexArgs = 0b00100;
        const FullRegexArgs = 0b01000;
        const FullWildcardPath = 0b10000;
    }
}

impl CmdMin {
    pub fn better(&self, other: &Self) -> bool {
        (!self.matching() && other.matching()) || (other.matching() && self.cmp(other) == Ordering::Less)
    }
    pub fn matching(&self) -> bool {
        !self.is_empty()
    }
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug, Default)]
pub enum CapsMin {
    #[default]
    Undefined,
    NoCaps,
    CapsNoAdmin(usize),
    CapsAdmin(usize),
    CapsAll,
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug, Default)]
pub struct SecurityMin(u32);

bitflags::bitflags! {

    impl SecurityMin: u32 {
        const DisableBounding   = 0b000001;
        const EnableRoot        = 0b000010;
        const KeepEnv           = 0b000100;
        const KeepPath          = 0b001000;
        const KeepUnsafePath    = 0b010000;
        const SkipAuth          = 0b100000;
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
pub struct TaskScore {
    pub cmd_min: CmdMin,
    pub caps_min: CapsMin,
    pub setuser_min: SetUserMin,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Default, Builder)]
pub struct Score {
    pub user_min: ActorMatchMin,
    pub cmd_min: CmdMin,
    pub caps_min: CapsMin,
    pub setuser_min: SetUserMin,
    pub security_min: SecurityMin,
}

impl Score {
    pub fn set_cmd_score(&mut self, cmd_min: CmdMin) {
        self.cmd_min = cmd_min;
    }
    pub fn set_task_score(&mut self, task_score: &TaskScore) {
        self.caps_min = task_score.caps_min;
        self.setuser_min = task_score.setuser_min;
    }
    pub fn set_role_score(&mut self, role_score: &ActorMatchMin) {
        self.user_min = *role_score;
    }
    pub fn prettyprint(&self) -> String {
        format!(
            "{:?}, {:?}, {:?}, {:?}, {:?}",
            self.user_min, self.cmd_min, self.caps_min, self.setuser_min, self.security_min
        )
    }

    pub fn user_cmp(&self, other: &Score) -> Ordering {
        self.user_min.cmp(&other.user_min)
    }

    /// Compare the score of tasks results
    pub fn cmd_cmp(&self, other: &Score) -> Ordering {
        self.cmd_min
            .cmp(&other.cmd_min)
            .then(self.caps_min.cmp(&other.caps_min))
            .then(self.setuser_min.cmp(&other.setuser_min))
            .then(self.security_min.cmp(&other.security_min))
    }

    pub fn user_matching(&self) -> bool {
        self.user_min != ActorMatchMin::NoMatch
    }

    pub fn command_matching(&self) -> bool {
        !self.cmd_min.is_empty()
    }

    pub fn fully_matching(&self) -> bool {
        self.user_matching() && self.command_matching()
    }

    /// Check if the current score is better than the other
    pub fn better_command(&self, other: &Score) -> bool {
        self.command_matching() && !(other.command_matching() || self.cmd_cmp(other) == Ordering::Less)
    }

    pub fn better_user(&self, other: &Score) -> bool {
        self.user_matching() && !(other.user_matching() || self.user_cmp(other) == Ordering::Less)
    }

    pub fn better_fully(&self, other: &Score) -> bool {
        self.fully_matching() && !(other.fully_matching() || self.cmp(other) == Ordering::Less)
    }
}

impl PartialOrd for Score {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Score {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmd_cmp(other).then(self.user_cmp(other))
    }

    fn max(self, other: Self) -> Self {
        std::cmp::max_by(self, other, Ord::cmp)
    }

    fn min(self, other: Self) -> Self {
        std::cmp::min_by(self, other, Ord::cmp)
    }

    fn clamp(self, min: Self, max: Self) -> Self {
        self.max(min).min(max)
    }
}



fn group_is_root(actortype: &SGroupType) -> bool {
    (*actortype).fetch_id().map_or(false, |id| id == 0)
}
fn dgroup_is_root(actortype: &DGroupType<'_>) -> bool {
    (*actortype).fetch_id().map_or(false, |id| id == 0)
}

fn user_is_root(actortype: &SUserType) -> bool {
    (*actortype).fetch_id().map_or(false, |id| id == 0)
}
fn duser_is_root(actortype: &DUserType<'_>) -> bool {
    (*actortype).fetch_id().map_or(false, |id| id == 0)
}

fn groups_contains_root(list: Option<&SGroups>) -> bool {
    if let Some(list) = list {
        match list {
            SGroups::Single(group) => group_is_root(group),
            SGroups::Multiple(groups) => groups.iter().any(group_is_root),
        }
    } else {
        false
    }
}

fn dgroups_contains_root(list: Option<&DGroups<'_>>) -> bool {
    if let Some(list) = list {
        match list {
            DGroups::Single(group) => dgroup_is_root(group),
            DGroups::Multiple(groups) => groups.iter().any(dgroup_is_root),
        }
    } else {
        false
    }
}

fn groups_len(groups: Option<&SGroups>) -> usize {
    match groups {
        Some(groups) => groups.len(),
        None => 0,
    }
}

fn dgroups_len(groups: Option<&DGroups<'_>>) -> usize {
    match groups {
        Some(groups) => groups.len(),
        None => 0,
    }
}