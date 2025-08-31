use std::cmp::Ordering;

use bon::{builder, Builder};
use strum::EnumIs;

use crate::util::{
    HARDENED_ENUM_VALUE_0, HARDENED_ENUM_VALUE_1, HARDENED_ENUM_VALUE_2, HARDENED_ENUM_VALUE_3,
    HARDENED_ENUM_VALUE_4,
};

use super::actor::{DGroupType, DGroups, DUserType, SGroupType, SGroups, SUserType};

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug, EnumIs, Default)]
#[repr(u32)]
// Matching user groups for the role
pub enum ActorMatchMin {
    UserMatch = HARDENED_ENUM_VALUE_0,
    GroupMatch(usize) = HARDENED_ENUM_VALUE_1,
    #[default]
    NoMatch = HARDENED_ENUM_VALUE_2,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, EnumIs, Default)]
#[repr(u32)]
pub enum HardenedBool {
    #[default]
    False = HARDENED_ENUM_VALUE_0,
    True = HARDENED_ENUM_VALUE_1,
}

impl ActorMatchMin {
    #[inline]
    pub fn better(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Less
    }
    #[inline]
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
        SetuidMin { is_root: s == 0 }
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
            nb_groups: dgroups_len(Some(s)),
        }
    }
}

impl From<&DGroupType<'_>> for SetgidMin {
    fn from(s: &DGroupType<'_>) -> Self {
        SetgidMin {
            is_root: dgroup_is_root(s),
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

#[derive(PartialEq, Eq, Clone, Copy, Debug, Default, Builder)]
#[builder(const)]
pub struct CmdMin {
    #[builder(default = HardenedBool::False, with = || HardenedBool::True, name = "matching")]
    pub status: HardenedBool,
    #[builder(default = CmdOrder::empty())]
    pub order: CmdOrder,
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug, Default)]
pub struct CmdOrder(u32);

bitflags::bitflags! {

    impl CmdOrder: u32 {
        const WildcardPath = 0b0001;
        const RegexArgs = 0b0010;
        const FullRegexArgs = 0b0100;
        const FullWildcardPath = 0b1000;
    }
}

impl CmdMin {
    pub const MATCH: CmdMin = CmdMin::builder().matching().build();

    pub const fn empty() -> Self {
        CmdMin::builder().build()
    }
    pub fn is_empty(&self) -> bool {
        self.status == HardenedBool::False && self.order.is_empty()
    }
    #[inline]
    pub fn better(&self, other: &Self) -> bool {
        (self.matching() && !other.matching())
            || (self.matching() && self.order.cmp(&other.order) == Ordering::Less)
    }
    #[inline]
    pub fn matching(&self) -> bool {
        self.status == HardenedBool::True
    }

    pub fn set_matching(&mut self) {
        self.status = HardenedBool::True;
    }

    pub fn union_order(&mut self, order: CmdOrder) {
        self.order |= order;
    }
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug, Default)]
#[repr(u32)]
pub enum CapsMin {
    #[default]
    Undefined = HARDENED_ENUM_VALUE_0,
    NoCaps = HARDENED_ENUM_VALUE_1,
    CapsNoAdmin(usize) = HARDENED_ENUM_VALUE_2,
    CapsAdmin(usize) = HARDENED_ENUM_VALUE_3,
    CapsAll = HARDENED_ENUM_VALUE_4,
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

#[derive(PartialEq, Eq, Clone, Copy, Debug, Default, Builder)]
pub struct TaskScore {
    #[builder(default)]
    pub cmd_min: CmdMin,
    #[builder(default)]
    pub caps_min: CapsMin,
    #[builder(default)]
    pub setuser_min: SetUserMin,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Default, Builder)]
pub struct Score {
    #[builder(default)]
    pub user_min: ActorMatchMin,
    #[builder(default)]
    pub cmd_min: CmdMin,
    #[builder(default)]
    pub caps_min: CapsMin,
    #[builder(default)]
    pub setuser_min: SetUserMin,
    #[builder(default)]
    pub security_min: SecurityMin,
}

impl Score {
    pub fn set_cmd_score(&mut self, cmd_min: CmdMin) {
        self.cmd_min = cmd_min;
    }
    pub fn set_task_score(&mut self, task_score: &TaskScore) {
        self.cmd_min = task_score.cmd_min;
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
    #[inline]
    pub fn cmd_cmp(&self, other: &Score) -> Ordering {
        self.cmd_min
            .order
            .cmp(&other.cmd_min.order)
            .then(self.caps_min.cmp(&other.caps_min))
            .then(self.setuser_min.cmp(&other.setuser_min))
            .then(self.security_min.cmp(&other.security_min))
    }

    #[inline]
    pub fn user_matching(&self) -> bool {
        self.user_min != ActorMatchMin::NoMatch
    }

    #[inline]
    pub fn command_matching(&self) -> bool {
        self.cmd_min.matching()
    }

    #[inline]
    pub fn fully_matching(&self) -> bool {
        self.user_matching() && self.command_matching()
    }

    /// Return true if the score is better than the other
    #[inline]
    pub fn better_command(&self, other: &Score) -> bool {
        (self.command_matching() && !other.command_matching())
            || (self.command_matching() && self.cmd_cmp(other) == Ordering::Less)
    }

    #[inline]
    pub fn better_user(&self, other: &Score) -> bool {
        (self.user_matching() && !other.user_matching())
            || (self.user_matching() && self.user_cmp(other) == Ordering::Less)
    }

    #[inline]
    pub fn better_fully(&self, other: &Score) -> bool {
        (self.fully_matching() && !other.fully_matching())
            || (self.fully_matching() && self.cmp(other) == Ordering::Less)
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

#[inline]
fn group_is_root(actortype: &SGroupType) -> bool {
    (*actortype).fetch_id() == Some(0)
}

#[inline]
fn dgroup_is_root(actortype: &DGroupType<'_>) -> bool {
    (*actortype).fetch_id() == Some(0)
}

#[inline]
fn user_is_root(actortype: &SUserType) -> bool {
    (*actortype).fetch_id() == Some(0)
}

#[inline]
fn duser_is_root(actortype: &DUserType<'_>) -> bool {
    (*actortype).fetch_id() == Some(0)
}

#[inline]
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

#[inline]
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

#[inline]
fn groups_len(groups: Option<&SGroups>) -> usize {
    match groups {
        Some(groups) => groups.len(),
        None => 0,
    }
}

#[inline]
fn dgroups_len(groups: Option<&DGroups<'_>>) -> usize {
    match groups {
        Some(groups) => groups.len(),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::actor::{DGroupType, DGroups, DUserType, SGroupType, SGroups, SUserType};
    use std::borrow::Cow;

    #[test]
    fn test_group_is_root() {
        let root_group = SGroupType::from(0);
        let non_root_group = SGroupType::from(1);
        assert!(group_is_root(&root_group));
        assert!(!group_is_root(&non_root_group));
    }

    #[test]
    fn test_dgroup_is_root() {
        let root_group = DGroupType::from(0);
        let non_root_group = DGroupType::from(1);
        assert!(dgroup_is_root(&root_group));
        assert!(!dgroup_is_root(&non_root_group));
    }

    #[test]
    fn test_user_is_root() {
        let root_user = SUserType::from(0);
        let non_root_user = SUserType::from(1);
        assert!(user_is_root(&root_user));
        assert!(!user_is_root(&non_root_user));
    }

    #[test]
    fn test_duser_is_root() {
        let root_user = DUserType::from(0);
        let non_root_user = DUserType::from(1);
        assert!(duser_is_root(&root_user));
        assert!(!duser_is_root(&non_root_user));
    }

    #[test]
    fn test_groups_contains_root() {
        let root_group = SGroupType::from(0);
        let non_root_group = SGroupType::from(1);
        let single = SGroups::Single(root_group.clone());
        let multiple = SGroups::from(vec![non_root_group.clone(), root_group.clone()]);
        let none = None;
        assert!(groups_contains_root(Some(&single)));
        assert!(groups_contains_root(Some(&multiple)));
        assert!(!groups_contains_root(Some(&SGroups::Single(
            non_root_group
        ))));
        assert!(!groups_contains_root(none));
    }

    #[test]
    fn test_dgroups_contains_root() {
        let root_group = DGroupType::from(0);
        let non_root_group = DGroupType::from(1);
        let single = DGroups::Single(root_group.clone());
        let multiple =
            DGroups::Multiple(Cow::Owned(vec![non_root_group.clone(), root_group.clone()]));
        let none = None;
        assert!(dgroups_contains_root(Some(&single)));
        assert!(dgroups_contains_root(Some(&multiple)));
        assert!(!dgroups_contains_root(Some(&DGroups::Single(
            non_root_group
        ))));
        assert!(!dgroups_contains_root(none));
    }

    #[test]
    fn test_groups_len() {
        let group1 = SGroupType::from(0);
        let single = SGroups::Single(group1);
        let multiple = SGroups::from(vec![SGroupType::from(0), SGroupType::from(1)]);
        assert_eq!(groups_len(Some(&single)), 1);
        assert_eq!(groups_len(Some(&multiple)), 2);
        assert_eq!(groups_len(None), 0);
    }

    #[test]
    fn test_dgroups_len() {
        let group1 = DGroupType::from(0);
        let single = DGroups::Single(group1);
        let multiple =
            DGroups::Multiple(Cow::Owned(vec![DGroupType::from(0), DGroupType::from(1)]));
        assert_eq!(dgroups_len(Some(&single)), 1);
        assert_eq!(dgroups_len(Some(&multiple)), 2);
        assert_eq!(dgroups_len(None), 0);
    }

    #[test]
    fn test_setgidmin_from_sgroups() {
        let groups = SGroups::from(vec![SGroupType::from(0), SGroupType::from(1)]);
        let setgid = SetgidMin::from(groups);
        assert!(setgid.is_root);
        assert_eq!(setgid.nb_groups, 2);
    }

    #[test]
    fn test_setgidmin_from_dgroups() {
        let groups = DGroups::from(vec![DGroupType::from(1), DGroupType::from(2)]);
        let setgid = SetgidMin::from(&groups);
        assert!(!setgid.is_root);
        assert_eq!(setgid.nb_groups, 2);
    }

    #[test]
    fn test_setgidmin_from_vec_u32() {
        let groups = vec![0, 1, 2];
        let setgid = SetgidMin::from(&groups);
        assert!(setgid.is_root);
        assert_eq!(setgid.nb_groups, 3);
    }

    #[test]
    fn test_setgidmin_from_dgrouptype() {
        let group = DGroupType::from(0);
        let setgid = SetgidMin::from(&group);
        assert!(setgid.is_root);
        assert_eq!(setgid.nb_groups, 1);
    }

    #[test]
    fn test_setuidmin_from_susertype() {
        let user = SUserType::from(0);
        let setuid = SetuidMin::from(user);
        assert!(setuid.is_root);
    }

    #[test]
    fn test_setuidmin_from_dusertype() {
        let user = DUserType::from(1);
        let setuid = SetuidMin::from(&user);
        assert!(!setuid.is_root);
    }

    #[test]
    fn test_setuidmin_from_u32() {
        let setuid = SetuidMin::from(0);
        assert!(setuid.is_root);
        let setuid = SetuidMin::from(1);
        assert!(!setuid.is_root);
    }

    #[test]
    fn test_score_ordering() {
        let score1 = Score::builder()
            .cmd_min(CmdMin::builder().matching().build())
            .build();
        let score2 = Score::builder()
            .cmd_min(
                CmdMin::builder()
                    .matching()
                    .order(CmdOrder::WildcardPath)
                    .build(),
            )
            .build();
        assert!(score1.better_command(&score2));
    }

    #[test]
    fn test_score_prettyprint() {
        let score = Score::default();
        let s = score.prettyprint();
        assert!(s.contains("NoMatch"));
    }

    #[test]
    fn test_cmdmin_better_and_matching() {
        let a = CmdMin::builder().matching().build();
        let b = CmdMin::builder().build();
        assert!(a.matching());
        assert!(!b.matching());
        assert!(!b.better(&a));
        assert!(a.better(&b));
    }

    #[test]
    fn test_score_better_methods() {
        let mut score1 = Score::default();
        let mut score2 = Score::default();
        score1.cmd_min = CmdMin::builder().matching().build();
        score2.cmd_min = CmdMin::builder().build();
        assert!(score1.better_command(&score2));
        assert!(!score2.better_command(&score1));
    }

    #[test]
    fn test_setuser_min_ordering() {
        let setuser1 = SetUserMin {
            uid: Some(SetuidMin::from(0)),
            gid: Some(SetgidMin::from(&vec![0])),
        };
        let setuser2 = SetUserMin {
            uid: Some(SetuidMin::from(1)),
            gid: Some(SetgidMin::from(&vec![1])),
        };
        assert!(setuser1 > setuser2);
    }

    #[test]
    fn test_setgidmin_ordering() {
        let setgid1 = SetgidMin {
            is_root: true,
            nb_groups: 2,
        };
        let setgid2 = SetgidMin {
            is_root: false,
            nb_groups: 3,
        };
        assert!(setgid1 > setgid2);
        assert!(setgid2 < setgid1);
        assert!(setgid1 != setgid2);
        let setgid2 = SetgidMin {
            is_root: true,
            nb_groups: 3,
        };
        assert!(setgid1 < setgid2);
        assert!(setgid2 > setgid1);
        assert!(setgid1 != setgid2);
    }

    #[test]
    fn test_actor_match_min() {
        let setuser = ActorMatchMin::UserMatch;
        assert!(setuser.matching());
        let setuser_other = ActorMatchMin::NoMatch;
        assert!(!setuser_other.matching());
        assert!(setuser.better(&setuser_other));
    }

    #[test]
    fn test_security_min() {
        let security = SecurityMin::empty();
        assert!(security.is_empty());
        let security_other = SecurityMin::DisableBounding;
        assert!(!security_other.is_empty());
        assert!(security < security_other);
        assert!(security_other > security);
        assert!(security_other != security);
        let security = SecurityMin::EnableRoot;
        assert!(security > security_other);
        assert!(security_other < security);
        assert!(security_other != security);
        let security_other = SecurityMin::KeepEnv;
        assert!(security_other > security);
        assert!(security < security_other);
        assert!(security_other != security);
        let security = SecurityMin::KeepPath;
        assert!(security > security_other);
        assert!(security_other < security);
        assert!(security_other != security);
        let security_other = SecurityMin::KeepUnsafePath;
        assert!(security_other > security);
        assert!(security < security_other);
        assert!(security_other != security);
        let security = SecurityMin::SkipAuth;
        assert!(security > security_other);
        assert!(security_other < security);
        assert!(security_other != security);
        let security_other = SecurityMin::empty();
        assert!(security > security_other);
        assert!(security_other < security);
    }
    #[test]
    fn test_set_score() {
        let mut score = Score::default();
        let task_score = TaskScore {
            cmd_min: CmdMin::builder().matching().build(),
            caps_min: CapsMin::NoCaps,
            setuser_min: SetUserMin::default(),
        };
        score.set_task_score(&task_score);
        assert_eq!(score.cmd_min, CmdMin::builder().matching().build());
        assert_eq!(score.caps_min, CapsMin::NoCaps);
        assert_eq!(score.setuser_min, SetUserMin::default());
        let role_score = ActorMatchMin::UserMatch;
        score.set_role_score(&role_score);
        assert_eq!(score.user_min, ActorMatchMin::UserMatch);
        assert_eq!(score.cmd_min, CmdMin::builder().matching().build());
        assert_eq!(score.caps_min, CapsMin::NoCaps);
        assert_eq!(score.setuser_min, SetUserMin::default());
        assert_eq!(score.security_min, SecurityMin::empty());
        score.set_cmd_score(
            CmdMin::builder()
                .matching()
                .order(CmdOrder::WildcardPath)
                .build(),
        );
        assert_eq!(
            score.cmd_min,
            CmdMin::builder()
                .matching()
                .order(CmdOrder::WildcardPath)
                .build()
        );
        assert_eq!(score.caps_min, CapsMin::NoCaps);
        assert_eq!(score.setuser_min, SetUserMin::default());
        assert_eq!(score.user_min, ActorMatchMin::UserMatch);
        assert_eq!(score.security_min, SecurityMin::empty());
    }

    #[test]
    fn test_score_matching() {
        let mut score = Score::default();
        assert!(!score.user_matching());
        assert!(!score.command_matching());
        assert!(!score.fully_matching());
        score.user_min = ActorMatchMin::UserMatch;
        assert!(score.user_matching());
        assert!(!score.command_matching());
        assert!(!score.fully_matching());
        score.cmd_min = CmdMin::builder().matching().build();
        assert!(score.user_matching());
        assert!(score.command_matching());
        assert!(score.fully_matching());
        score.user_min = ActorMatchMin::NoMatch;
        assert!(!score.user_matching());
        assert!(score.command_matching());
        assert!(!score.fully_matching());
    }

    #[test]
    fn test_score_better() {
        let mut score1 = Score::default();
        let mut score2 = Score::default();
        score1.cmd_min = CmdMin::builder().matching().build();
        score2.cmd_min = CmdMin::builder()
            .matching()
            .order(CmdOrder::WildcardPath)
            .build();
        assert!(!score2.better_command(&score1));
        assert!(score1.better_command(&score2));
        assert!(!score1.better_user(&score2));
        assert!(!score2.better_user(&score1));
        assert!(!score1.better_fully(&score2));
        assert!(!score2.better_fully(&score1));
        score1.user_min = ActorMatchMin::UserMatch;
        score2.user_min = ActorMatchMin::GroupMatch(1);
        assert!(score1.better_user(&score2));
        assert!(!score2.better_user(&score1));
        assert!(score1.better_fully(&score2));
        assert!(!score2.better_fully(&score1));
    }

    #[test]
    fn test_score_max_min_clamp() {
        let mut score1 = Score::default();
        let mut score2 = Score::default();
        score1.cmd_min = CmdMin::builder().matching().build();
        score2.cmd_min = CmdMin::builder()
            .matching()
            .order(CmdOrder::WildcardPath)
            .build();
        assert_eq!(score1.max(score2), score2);
        assert_eq!(score2.max(score1), score2);
        assert_eq!(score1.min(score2), score1);
        assert_eq!(score2.min(score1), score1);
        let score3 = Score::builder()
            .cmd_min(
                CmdMin::builder()
                    .matching()
                    .order(CmdOrder::RegexArgs)
                    .build(),
            )
            .build();
        assert_eq!(score1.clamp(score2, score3), score2);
        assert_eq!(score2.clamp(score1, score3), score2);
    }
}
