//! "Collections" panel of the detail pane, modelled on the official clients' "Assign collections":
//! a personal item picks an organization and moves there for good; an organization item only
//! changes which of that organization's collections it is in.

use std::sync::Arc;

use bwl_vault::model::{CollectionView, OrganizationView};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub id: Arc<str>,
    pub name: Arc<str>,
    pub checked: bool,
    /// Read-only collections the item is in are listed checked, but the user can't take it out.
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignForm {
    organizations: Vec<OrganizationView>,
    /// The item already belongs to `organizations[0]`, the only one listed.
    fixed: bool,
    organization: usize,
    current: Vec<Arc<str>>,
    collections: Vec<CollectionView>,
    choices: Vec<Choice>,
}

/// The item's collections by name, in name order.
#[must_use]
pub fn collection_names(current: &[Arc<str>], collections: &[CollectionView]) -> String {
    let mut names: Vec<&str> = collections
        .iter()
        .filter(|collection| current.contains(&collection.id))
        .map(|collection| collection.name.as_ref())
        .collect();
    names.sort_by_cached_key(|name| name.to_lowercase());
    names.join(", ")
}

/// Whether the panel has anything to offer: an organization the item can move to or is in.
#[must_use]
pub fn available(organization_id: Option<&Arc<str>>, organizations: &[OrganizationView]) -> bool {
    match organization_id {
        Some(id) => organizations
            .iter()
            .any(|organization| &organization.id == id),
        None => !organizations.is_empty(),
    }
}

impl AssignForm {
    /// `None` when [`available`] is false.
    #[must_use]
    pub fn open(
        organization_id: Option<&Arc<str>>,
        current: &[Arc<str>],
        organizations: &[OrganizationView],
        collections: &[CollectionView],
    ) -> Option<Self> {
        let mut listed: Vec<OrganizationView> = match organization_id {
            Some(id) => organizations
                .iter()
                .filter(|organization| &organization.id == id)
                .cloned()
                .collect(),
            None => organizations.to_vec(),
        };
        if listed.is_empty() {
            return None;
        }
        listed.sort_by_cached_key(|organization| organization.name.to_lowercase());
        let mut form = Self {
            organizations: listed,
            fixed: organization_id.is_some(),
            organization: 0,
            current: current.to_vec(),
            collections: collections.to_vec(),
            choices: Vec::new(),
        };
        form.choices = form.choices_for(0);
        Some(form)
    }

    fn choices_for(&self, organization: usize) -> Vec<Choice> {
        let Some(organization) = self.organizations.get(organization) else {
            return Vec::new();
        };
        let mut choices: Vec<Choice> = self
            .collections
            .iter()
            .filter(|collection| collection.organization_id == organization.id)
            .filter_map(|collection| {
                let checked = self.current.contains(&collection.id);
                (checked || !collection.read_only).then(|| Choice {
                    id: Arc::clone(&collection.id),
                    name: Arc::clone(&collection.name),
                    checked,
                    enabled: !collection.read_only,
                })
            })
            .collect();
        choices.sort_by_cached_key(|choice| choice.name.to_lowercase());
        choices
    }

    pub fn pick_organization(&mut self, index: usize) {
        if self.fixed || index >= self.organizations.len() || index == self.organization {
            return;
        }
        self.organization = index;
        self.choices = self.choices_for(index);
    }

    pub fn toggle(&mut self, index: usize, checked: bool) {
        if let Some(choice) = self.choices.get_mut(index)
            && choice.enabled
        {
            choice.checked = checked;
        }
    }

    #[must_use]
    pub fn organization_labels(&self) -> Vec<Arc<str>> {
        self.organizations
            .iter()
            .map(|organization| Arc::clone(&organization.name))
            .collect()
    }

    #[must_use]
    pub const fn organization_index(&self) -> usize {
        self.organization
    }

    #[must_use]
    pub const fn fixed(&self) -> bool {
        self.fixed
    }

    #[must_use]
    pub fn choices(&self) -> &[Choice] {
        &self.choices
    }

    #[must_use]
    pub fn organization_id(&self) -> &Arc<str> {
        &self.organizations[self.organization].id
    }

    /// The checked collections the user may change; the vault keeps the read-only ones.
    #[must_use]
    pub fn picked(&self) -> Vec<Arc<str>> {
        self.choices
            .iter()
            .filter(|choice| choice.enabled && choice.checked)
            .map(|choice| Arc::clone(&choice.id))
            .collect()
    }

    /// The server needs at least one collection, and an unchanged set is no change.
    #[must_use]
    pub fn can_submit(&self) -> bool {
        let picked = self.picked();
        if picked.is_empty() {
            return false;
        }
        if !self.fixed {
            return true;
        }
        let editable_now: Vec<&Arc<str>> = self
            .choices
            .iter()
            .filter(|choice| choice.enabled && self.current.contains(&choice.id))
            .map(|choice| &choice.id)
            .collect();
        picked.len() != editable_now.len() || picked.iter().any(|id| !editable_now.contains(&id))
    }

    /// What the user should know before a personal item changes owner.
    #[must_use]
    pub fn warning(&self) -> String {
        if self.fixed {
            return String::new();
        }
        format!(
            "Ownership moves to {}. The item can't be moved back to your personal vault.",
            self.organizations[self.organization].name
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org(id: &str, name: &str) -> OrganizationView {
        OrganizationView {
            id: id.into(),
            name: name.into(),
        }
    }

    fn collection(id: &str, organization_id: &str, name: &str, read_only: bool) -> CollectionView {
        CollectionView {
            id: id.into(),
            organization_id: organization_id.into(),
            name: name.into(),
            read_only,
        }
    }

    fn ids(list: &[&str]) -> Vec<Arc<str>> {
        list.iter().map(|id| Arc::from(*id)).collect()
    }

    fn organizations() -> Vec<OrganizationView> {
        vec![org("zeta", "Zeta"), org("acme", "Acme")]
    }

    fn collections() -> Vec<CollectionView> {
        vec![
            collection("eng", "acme", "Engineering", false),
            collection("fin", "acme", "Finance", true),
            collection("ops", "acme", "Operations", false),
            collection("z1", "zeta", "Zeta shared", false),
            collection("z2", "zeta", "Zeta audit", true),
        ]
    }

    fn names(form: &AssignForm) -> Vec<&str> {
        form.choices()
            .iter()
            .map(|choice| choice.name.as_ref())
            .collect()
    }

    #[test]
    fn a_personal_item_picks_among_all_organizations_and_their_writable_collections() {
        let form = AssignForm::open(None, &[], &organizations(), &collections())
            .expect("an organization to offer");
        assert!(!form.fixed());
        assert_eq!(
            form.organization_labels(),
            [Arc::from("Acme"), Arc::from("Zeta")]
        );
        assert_eq!(&**form.organization_id(), "acme");
        assert_eq!(names(&form), ["Engineering", "Operations"]);
        assert!(!form.can_submit(), "at least one collection is required");
        assert!(form.warning().contains("Acme"));
    }

    #[test]
    fn switching_organization_lists_its_collections_and_drops_the_old_picks() {
        let mut form = AssignForm::open(None, &[], &organizations(), &collections())
            .expect("an organization to offer");
        form.toggle(0, true);
        form.pick_organization(1);
        assert_eq!(&**form.organization_id(), "zeta");
        assert_eq!(names(&form), ["Zeta shared"]);
        assert_eq!(form.picked(), Vec::<Arc<str>>::new());
        form.toggle(0, true);
        assert_eq!(form.picked(), ids(&["z1"]));
        assert!(form.can_submit());
    }

    #[test]
    fn an_organization_item_stays_in_its_organization_and_keeps_read_only_collections() {
        let mut form = AssignForm::open(
            Some(&Arc::from("acme")),
            &ids(&["eng", "fin"]),
            &organizations(),
            &collections(),
        )
        .expect("the item's organization");
        assert!(form.fixed());
        assert_eq!(form.organization_labels(), [Arc::from("Acme")]);
        assert_eq!(names(&form), ["Engineering", "Finance", "Operations"]);
        let finance = &form.choices()[1];
        assert!(finance.checked && !finance.enabled);
        assert_eq!(form.warning(), "");
        assert!(!form.can_submit(), "nothing changed yet");

        form.toggle(1, false);
        assert!(form.choices()[1].checked, "read-only stays checked");
        form.toggle(0, false);
        assert!(!form.can_submit(), "only the read-only collection is left");
        form.toggle(2, true);
        assert_eq!(form.picked(), ids(&["ops"]));
        assert!(form.can_submit());
        form.pick_organization(1);
        assert_eq!(&**form.organization_id(), "acme");
    }

    #[test]
    fn nothing_to_offer_without_organizations() {
        assert!(!available(None, &[]));
        assert!(available(None, &organizations()));
        assert!(!available(Some(&Arc::from("gone")), &organizations()));
        assert!(AssignForm::open(None, &[], &[], &collections()).is_none());
    }

    #[test]
    fn collection_names_are_listed_in_name_order() {
        assert_eq!(
            collection_names(&ids(&["ops", "eng", "missing"]), &collections()),
            "Engineering, Operations"
        );
        assert_eq!(collection_names(&[], &collections()), "");
    }
}
