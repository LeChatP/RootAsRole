use cursive::{
    align::{Align, HAlign, VAlign},
    direction,
    event::{Callback, Event, EventResult, Key, MouseButton, MouseEvent},
    impl_enabled, menu,
    theme::ColorStyle,
    utils::{markup::StyledString, span::SpannedStr},
    view::{CannotFocus, Position, View},
    views::{LayerPosition, MenuPopup},
    Cursive, Printer, Rect, Vec2, With, XY,
};
use std::cell::Cell;
use std::cmp::{min, Ordering};
use std::rc::Rc;

type SelectCallback<T> = dyn Fn(&mut Cursive, bool, &T);

/// View to select an item among a list.
///
/// It contains a list of values of type T, with associated labels.
///
/// # Examples
///
/// ```rust
/// # use cursive_core::Cursive;
/// # use cursive_core::views::{CheckListView, Dialog, TextView};
/// # use cursive_core::align::HAlign;
/// let mut time_select = CheckListView::new().h_align(HAlign::Center);
/// time_select.add_item("Short", 1);
/// time_select.add_item("Medium", 5);
/// time_select.add_item("Long", 10);
///
/// time_select.set_on_submit(|s, time| {
///     s.pop_layer();
///     let text = format!("You will wait for {} minutes...", time);
///     s.add_layer(
///         Dialog::around(TextView::new(text)).button("Quit", |s| s.quit()),
///     );
/// });
///
/// let mut siv = Cursive::new();
/// siv.add_layer(Dialog::around(time_select).title("How long is your wait?"));
/// ```
pub struct CheckListView<T = String> {
    // The core of the view: we store a list of items
    // `Item` is more or less a `(String, Rc<T>)`.
    items: Vec<Item<T>>,

    // When disabled, we cannot change selection.
    enabled: bool,

    // Callbacks may need to manipulate focus, so give it some mutability.
    focus: Rc<Cell<usize>>,

    // This callback is called when the selection is changed.
    // TODO: add the previous selection? Indices?
    on_select: Option<Rc<SelectCallback<T>>>,

    // This callback is called when the user presses `Enter`.
    on_submit: Option<Rc<SelectCallback<T>>>,

    // If `true`, when a character is pressed, jump to the next item starting
    // with this character.
    autojump: bool,

    align: Align,

    // `true` if we show a one-line view, with popup on selection.
    popup: bool,

    // We need the last offset to place the popup window
    // We "cache" it during the draw, so we need interior mutability.
    last_offset: Cell<Vec2>,
    last_size: Vec2,

    // Cache of required_size. Set to None when it needs to be recomputed.
    last_required_size: Option<Vec2>,
}

impl<T: 'static> Default for CheckListView<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: 'static> CheckListView<T> {
    impl_enabled!(self.enabled);

    /// Creates a new empty CheckListView.
    pub fn new() -> Self {
        CheckListView {
            items: Vec::new(),
            enabled: true,
            focus: Rc::new(Cell::new(0)),
            on_select: None,
            on_submit: None,
            align: Align::top_left(),
            popup: false,
            autojump: false,
            last_offset: Cell::new(Vec2::zero()),
            last_size: Vec2::zero(),
            last_required_size: None,
        }
    }

    /// Sets the "auto-jump" property for this view.
    ///
    /// If enabled, when a key is pressed, the selection will jump to the next
    /// item beginning with the pressed letter.
    pub fn set_autojump(&mut self, autojump: bool) {
        self.autojump = autojump;
    }

    /// Sets the "auto-jump" property for this view.
    ///
    /// If enabled, when a key is pressed, the selection will jump to the next
    /// item beginning with the pressed letter.
    ///
    /// Chainable variant.
    #[must_use]
    pub fn autojump(self) -> Self {
        self.with(|s| s.set_autojump(true))
    }

    /// Turns `self` into a popup select view.
    ///
    /// Chainable variant.
    #[must_use]
    pub fn popup(self) -> Self {
        self.with(|s| s.set_popup(true))
    }

    /// Turns `self` into a popup select view.
    pub fn set_popup(&mut self, popup: bool) {
        self.popup = popup;
        self.last_required_size = None;
    }

    /// Sets a callback to be used when an item is selected.
    pub fn set_on_select<F>(&mut self, cb: F)
    where
        F: Fn(&mut Cursive, bool, &T) + 'static,
    {
        self.on_select = Some(Rc::new(cb));
    }

    pub fn set_on_submit<F>(&mut self, cb: F)
    where
        F: Fn(&mut Cursive, bool, &T) + 'static,
    {
        self.on_submit = Some(Rc::new(cb));
    }

    /// Sets a callback to be used when an item is selected.
    ///
    /// Chainable variant.
    ///
    /// # Examples
    ///
    /// ```
    /// use cursive_core::traits::Nameable;
    /// use cursive_core::views::{CheckListView, TextView};
    ///
    /// let text_view = TextView::new("").with_name("text");
    ///
    /// let select_view = CheckListView::new()
    ///     .item("One", 1)
    ///     .item("Two", 2)
    ///     .on_select(|s, item| {
    ///         let content = match *item {
    ///             1 => "Content number one",
    ///             2 => "Content number two! Much better!",
    ///             _ => unreachable!("no such item"),
    ///         };
    ///
    ///         // Update the textview with the currently selected item.
    ///         s.call_on_name("text", |v: &mut TextView| {
    ///             v.set_content(content);
    ///         })
    ///         .unwrap();
    ///     });
    /// ```
    #[must_use]
    pub fn on_select<F>(self, cb: F) -> Self
    where
        F: Fn(&mut Cursive, bool, &T) + 'static,
    {
        self.with(|s| s.set_on_select(cb))
    }

    #[must_use]
    pub fn on_submit<F>(self, cb: F) -> Self
    where
        F: Fn(&mut Cursive, bool, &T) + 'static,
    {
        self.with(|s| s.set_on_submit(cb))
    }

    /// Sets the alignment for this view.
    ///
    /// # Examples
    ///
    /// ```
    /// use cursive_core::align;
    /// use cursive_core::views::CheckListView;
    ///
    /// let select_view = CheckListView::new()
    ///     .item("One", 1)
    ///     .align(align::Align::top_center());
    /// ```
    #[must_use]
    pub fn align(mut self, align: Align) -> Self {
        self.align = align;

        self
    }

    /// Sets the vertical alignment for this view.
    /// (If the view is given too much space vertically.)
    #[must_use]
    pub fn v_align(mut self, v: VAlign) -> Self {
        self.align.v = v;

        self
    }

    /// Sets the horizontal alignment for this view.
    #[must_use]
    pub fn h_align(mut self, h: HAlign) -> Self {
        self.align.h = h;

        self
    }

    /// Returns the value of the currently selected item.
    ///
    /// Returns `None` if the list is empty.
    pub fn selection(&self) -> Option<(bool, Rc<T>)> {
        let focus = self.focus();
        if self.len() <= focus {
            None
        } else {
            let item = &self.items[focus];
            Some((item.checked, item.value.clone()))
        }
    }

    pub fn is_checked(&self) -> bool {
        let focus = self.focus();
        if self.len() <= focus {
            false
        } else {
            self.items[focus].checked
        }
    }

    /// Removes all items from this view.
    pub fn clear(&mut self) {
        self.items.clear();
        self.focus.set(0);
        self.last_required_size = None;
    }

    /// Adds a item to the list, with given label and value.
    ///
    /// # Examples
    ///
    /// ```
    /// use cursive_core::views::CheckListView;
    ///
    /// let mut select_view = CheckListView::new();
    ///
    /// select_view.add_item("Item 1", 1);
    /// select_view.add_item("Item 2", 2);
    /// ```
    pub fn add_item<S: Into<StyledString>>(&mut self, label: S, checked: bool, value: T) {
        self.items.push(Item::new(label.into(), checked, value));
        self.last_required_size = None;
    }

    /// Gets an item at given idx or None.
    ///
    /// ```
    /// use cursive_core::views::{CheckListView, TextView};
    /// use cursive_core::Cursive;
    /// let select = CheckListView::new().item("Short", 1);
    /// assert_eq!(select.get_item(0), Some(("Short", &1)));
    /// ```
    pub fn get_item(&self, i: usize) -> Option<(&str, &bool, &T)> {
        self.iter().nth(i)
    }

    /// Gets a mut item at given idx or None.
    pub fn get_item_mut(&mut self, i: usize) -> Option<(&mut StyledString, &mut bool, &mut T)> {
        if i >= self.items.len() {
            None
        } else {
            self.last_required_size = None;
            let item = &mut self.items[i];
            if let Some(t) = Rc::get_mut(&mut item.value) {
                let label = &mut item.label;
                Some((label, &mut item.checked, t))
            } else {
                None
            }
        }
    }

    pub fn get_selected_item_mut(&mut self) -> Option<(&mut StyledString, &mut bool, &mut T)> {
        self.get_item_mut(self.focus())
    }

    pub fn get_checked_item_mut(&mut self) -> Vec<(&mut StyledString, &mut T)> {
        self.items
            .iter_mut()
            .filter(|item| item.checked)
            .map(|item| {
                let label = &mut item.label;
                let value = Rc::get_mut(&mut item.value).unwrap();
                (label, value)
            })
            .collect()
    }

    pub fn get_checked_item(&self) -> Vec<(StyledString, &T)> {
        self.items
            .iter()
            .filter(|item| item.checked)
            .map(|item| {
                let label = item.label.to_owned();
                let value = &*item.value;
                (label, value)
            })
            .collect()
    }

    /// Iterate mutably on the items in this view.
    ///
    /// Returns an iterator with each item and their labels.
    ///
    /// In some cases some items will need to be cloned (for example if a
    /// `Rc<T>` is still alive after calling `CheckListView::selection()`).
    ///
    /// If `T` does not implement `Clone`, check `CheckListView::try_iter_mut()`.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&mut StyledString, &mut bool, &mut T)>
    where
        T: Clone,
    {
        self.last_required_size = None;
        self.items.iter_mut().map(|item| {
            (
                &mut item.label,
                &mut item.checked,
                Rc::make_mut(&mut item.value),
            )
        })
    }

    /// Try to iterate mutably on the items in this view.
    ///
    /// Returns an iterator with each item and their labels.
    ///
    /// Some items may not be returned mutably, for example if a `Rc<T>` is
    /// still alive after calling `CheckListView::selection()`.
    pub fn try_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (&mut StyledString, &mut bool, Option<&mut T>)> {
        self.last_required_size = None;
        self.items.iter_mut().map(|item| {
            (
                &mut item.label,
                &mut item.checked,
                Rc::get_mut(&mut item.value),
            )
        })
    }

    /// Iterate on the items in this view.
    ///
    /// Returns an iterator with each item and their labels.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &bool, &T)> {
        self.items
            .iter()
            .map(|item| (item.label.source(), &item.checked, &*item.value))
    }

    /// Iterate on the items in this view.
    ///
    /// Returns an iterator with each item and their labels.
    pub fn iter_checked(&self) -> impl Iterator<Item = (&str, &T)> {
        self.items.iter().filter_map(|item| {
            if item.checked {
                Some((item.label.source(), &*item.value))
            } else {
                None
            }
        })
    }

    /// Removes an item from the list.
    ///
    /// Returns a callback in response to the selection change.
    ///
    /// You should run this callback with a `&mut Cursive`.
    pub fn remove_item(&mut self, id: usize) -> Callback {
        self.items.remove(id);
        self.last_required_size = None;
        let focus = self.focus();
        (focus >= id && focus > 0)
            .then(|| {
                self.focus.set(focus - 1);
                self.make_select_cb()
            })
            .flatten()
            .unwrap_or_else(Callback::dummy)
    }

    /// Inserts an item at position `index`, shifting all elements after it to
    /// the right.
    pub fn insert_item<S>(&mut self, index: usize, label: S, checked: bool, value: T)
    where
        S: Into<StyledString>,
    {
        self.items
            .insert(index, Item::new(label.into(), checked, value));
        let focus = self.focus();
        if focus >= index {
            self.focus.set(focus + 1);
        }
        self.last_required_size = None;
    }

    /// Chainable variant of add_item
    ///
    /// # Examples
    ///
    /// ```
    /// use cursive_core::views::CheckListView;
    ///
    /// let select_view = CheckListView::new()
    ///     .item("Item 1", 1)
    ///     .item("Item 2", 2)
    ///     .item("Surprise item", 42);
    /// ```
    #[must_use]
    pub fn item<S: Into<StyledString>>(self, label: S, checked: bool, value: T) -> Self {
        self.with(|s| s.add_item(label, checked, value))
    }

    /// Adds all items from from an iterator.
    pub fn add_all<S, I>(&mut self, iter: I)
    where
        S: Into<StyledString>,
        I: IntoIterator<Item = (S, bool, T)>,
    {
        for (s, c, t) in iter {
            self.add_item(s, c, t);
        }
    }

    /// Adds all items from from an iterator.
    ///
    /// Chainable variant.
    ///
    /// # Examples
    ///
    /// ```
    /// use cursive_core::views::CheckListView;
    ///
    /// // Create a CheckListView with 100 items
    /// let select_view = CheckListView::new()
    ///     .with_all((1u8..100).into_iter().map(|i| (format!("Item {}", i), i)));
    /// ```
    #[must_use]
    pub fn with_all<S, I>(self, iter: I) -> Self
    where
        S: Into<StyledString>,
        I: IntoIterator<Item = (S, bool, T)>,
    {
        self.with(|s| s.add_all(iter))
    }

    fn draw_item(&self, printer: &Printer, i: usize) {
        let l = self.items[i].label.width() + 4;
        let x = self.align.h.get_offset(l, printer.size.x);
        printer.print_hline::<XY<usize>>(XY::new(0, 0), x, " ");
        printer.print(XY::new(0, 0), "[ ] ");
        if self.items[i].checked {
            printer.print(XY::new(1, 0), "X");
        }
        printer.print_styled(XY::new(x + 4, 0), SpannedStr::from(&self.items[i].label));
        if l < printer.size.x {
            assert!((l + x) <= printer.size.x);
            printer.print_hline(XY::new(x + l, 0), printer.size.x - (l + x), " ");
        }
    }

    /// Returns the id of the item currently selected.
    ///
    /// Returns `None` if the list is empty.
    pub fn selected_id(&self) -> Option<usize> {
        if self.items.is_empty() {
            None
        } else {
            Some(self.focus())
        }
    }

    /// Returns the number of items in this list.
    ///
    /// # Examples
    ///
    /// ```
    /// use cursive_core::views::CheckListView;
    ///
    /// let select_view = CheckListView::new()
    ///     .item("Item 1", 1)
    ///     .item("Item 2", 2)
    ///     .item("Item 3", 3);
    ///
    /// assert_eq!(select_view.len(), 3);
    /// ```
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` if this list has no item.
    ///
    /// # Examples
    ///
    /// ```
    /// use cursive_core::views::CheckListView;
    ///
    /// let mut select_view = CheckListView::new();
    /// assert!(select_view.is_empty());
    ///
    /// select_view.add_item("Item 1", 1);
    /// select_view.add_item("Item 2", 2);
    /// assert!(!select_view.is_empty());
    ///
    /// select_view.clear();
    /// assert!(select_view.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    fn focus(&self) -> usize {
        self.focus.get()
    }

    /// Sort the current items lexicographically by their label.
    ///
    /// Note that this does not change the current focus index, which means that the current
    /// selection will likely be changed by the sorting.
    ///
    /// This sort is stable: items with identical label will not be reordered.
    pub fn sort_by_label(&mut self) {
        self.items
            .sort_by(|a, b| a.label.source().cmp(b.label.source()));
    }

    /// Sort the current items with the given comparator function.
    ///
    /// Note that this does not change the current focus index, which means that the current
    /// selection will likely be changed by the sorting.
    ///
    /// The given comparator function must define a total order for the items.
    ///
    /// If the comparator function does not define a total order, then the order after the sort is
    /// unspecified.
    ///
    /// This sort is stable: equal items will not be reordered.
    pub fn sort_by<F>(&mut self, mut compare: F)
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        self.items.sort_by(|a, b| compare(&a.value, &b.value));
    }

    /// Sort the current items with the given key extraction function.
    ///
    /// Note that this does not change the current focus index, which means that the current
    /// selection will likely be changed by the sorting.
    ///
    /// This sort is stable: items with equal keys will not be reordered.
    pub fn sort_by_key<K, F>(&mut self, mut key_of: F)
    where
        F: FnMut(&T) -> K,
        K: Ord,
    {
        self.items.sort_by_key(|item| key_of(&item.value));
    }

    /// Moves the selection to the given position.
    ///
    /// Returns a callback in response to the selection change.
    ///
    /// You should run this callback with a `&mut Cursive`.
    pub fn set_selection(&mut self, i: usize) -> Callback {
        // TODO: Check if `i >= self.len()` ?
        // assert!(i < self.len(), "CheckListView: trying to select out-of-bound");
        // Or just cap the ID?
        let i = if self.is_empty() {
            0
        } else {
            min(i, self.len() - 1)
        };
        self.focus.set(i);

        self.make_select_cb().unwrap_or_else(Callback::dummy)
    }

    /// Sets the selection to the given position.
    ///
    /// Chainable variant.
    ///
    /// Does not apply `on_select` callbacks.
    #[must_use]
    pub fn selected(self, i: usize) -> Self {
        self.with(|s| {
            s.set_selection(i);
        })
    }

    /// Moves the selection up by the given number of rows.
    ///
    /// Returns a callback in response to the selection change.
    ///
    /// You should run this callback with a `&mut Cursive`:
    ///
    /// ```rust
    /// # use cursive_core::Cursive;
    /// # use cursive_core::views::CheckListView;
    /// fn select_up(siv: &mut Cursive, view: &mut CheckListView<()>) {
    ///     let cb = view.select_up(1);
    ///     cb(siv);
    /// }
    /// ```
    pub fn select_up(&mut self, n: usize) -> Callback {
        self.focus_up(n);
        self.make_select_cb().unwrap_or_else(Callback::dummy)
    }

    /// Moves the selection down by the given number of rows.
    ///
    /// Returns a callback in response to the selection change.
    ///
    /// You should run this callback with a `&mut Cursive`.
    pub fn select_down(&mut self, n: usize) -> Callback {
        self.focus_down(n);
        self.make_select_cb().unwrap_or_else(Callback::dummy)
    }

    fn focus_up(&mut self, n: usize) {
        let focus = self.focus().saturating_sub(n);
        self.focus.set(focus);
    }

    fn focus_down(&mut self, n: usize) {
        let focus = min(self.focus() + n, self.items.len().saturating_sub(1));
        self.focus.set(focus);
    }

    fn submit(&mut self) -> EventResult {
        let item = self.get_selected_item_mut();
        if let Some(item) = item {
            *item.1 = !*item.1;
        }
        EventResult::Consumed(self.make_submit_cb())
    }

    fn toggleall(&mut self) -> EventResult {
        for item in self.try_iter_mut() {
            *item.1 = !*item.1;
        }
        EventResult::Consumed(self.make_submit_cb())
    }

    fn uncheckall(&mut self) -> EventResult {
        for item in self.try_iter_mut() {
            *item.1 = false;
        }
        EventResult::Consumed(self.make_submit_cb())
    }

    fn checkall(&mut self) -> EventResult {
        // make event for each items

        for item in self.try_iter_mut() {
            *item.1 = true;
        }
        EventResult::Consumed(self.make_submit_cb())
    }

    fn on_char_event(&mut self, c: char) -> EventResult {
        let i = {
            // * Starting from the current focus, find the first item that
            //   match the char.
            // * Cycle back to the beginning of the list when we reach the end.
            // * This is achieved by chaining twice the iterator.
            let iter = self.iter().chain(self.iter());

            // We'll do a lowercase check.
            let lower_c: Vec<char> = c.to_lowercase().collect();
            let lower_c: &[char] = &lower_c;

            if let Some((i, _)) = iter
                .enumerate()
                .skip(self.focus() + 1)
                .find(|&(_, (label, _, _))| label.to_lowercase().starts_with(lower_c))
            {
                i % self.len()
            } else {
                return EventResult::Ignored;
            }
        };

        self.focus.set(i);
        // Apply modulo in case we have a hit from the chained iterator
        let cb = self.set_selection(i);
        EventResult::Consumed(Some(cb))
    }

    fn on_event_regular(&mut self, event: Event) -> EventResult {
        match event {
            Event::Key(Key::Up) if self.focus() > 0 => self.focus_up(1),
            Event::Key(Key::Down) if self.focus() + 1 < self.items.len() => self.focus_down(1),
            Event::Key(Key::PageUp) => self.focus_up(10),
            Event::Key(Key::PageDown) => self.focus_down(10),
            Event::Key(Key::Home) => self.focus.set(0),
            Event::Key(Key::End) => self.focus.set(self.items.len().saturating_sub(1)),
            Event::Mouse {
                event: MouseEvent::Press(_),
                position,
                offset,
            } if position
                .checked_sub(offset)
                .map(|position| position < self.last_size && position.y < self.len())
                .unwrap_or(false) =>
            {
                self.focus.set(position.y - offset.y)
            }
            Event::Mouse {
                event: MouseEvent::Release(MouseButton::Left),
                position,
                offset,
            } if position
                .checked_sub(offset)
                .map(|position| position < self.last_size && position.y == self.focus())
                .unwrap_or(false) =>
            {
                return self.submit();
            }
            Event::Char(' ') | Event::Key(Key::Enter) => return self.submit(),
            Event::CtrlChar('a') => return self.checkall(),
            Event::CtrlChar('u') => return self.uncheckall(),
            Event::CtrlChar('d') => return self.toggleall(),
            Event::Char(c) if self.autojump => return self.on_char_event(c),
            _ => return EventResult::Ignored,
        }

        EventResult::Consumed(self.make_select_cb())
    }

    /// Returns a callback from selection change.
    fn make_select_cb(&self) -> Option<Callback> {
        self.on_select.to_owned().and_then(|cb| {
            self.selection()
                .map(|(b, v)| Callback::from_fn(move |s| cb(s, b, &v)))
        })
    }

    /// Returns a callback from submit change.
    fn make_submit_cb(&self) -> Option<Callback> {
        self.on_submit.to_owned().and_then(|cb| {
            self.selection()
                .map(|(b, v)| Callback::from_fn(move |s: &mut Cursive| cb(s, b, &v)))
        })
    }

    fn open_popup(&mut self) -> EventResult {
        // Build a shallow menu tree to mimick the items array.
        // TODO: cache it?
        let mut tree = menu::Tree::new();
        for (i, item) in self.items.iter().enumerate() {
            let focus: Rc<Cell<usize>> = Rc::clone(&self.focus);
            tree.add_leaf(item.label.source(), move |_| {
                // TODO: What if an item was removed in the meantime?
                focus.set(i);
            });
        }
        // Let's keep the tree around,
        // the callback will want to use it.
        let tree = Rc::new(tree);

        let focus = self.focus();
        // This is the offset for the label text.
        // We'll want to show the popup so that the text matches.
        // It'll be soo cool.
        let item_length = self.items[focus].label.width();
        let text_offset = (self.last_size.x.saturating_sub(item_length)) / 2;
        // The total offset for the window is:
        // * the last absolute offset at which we drew this view
        // * shifted to the right of the text offset
        // * shifted to the top of the focus (so the line matches)
        // * shifted top-left of the border+padding of the popup
        let offset = self.last_offset.get();
        let offset = offset + (text_offset, 0);
        let offset = offset.saturating_sub((0, focus));
        let offset = offset.saturating_sub::<XY<usize>>(XY::new(2, 1));

        // And now, we can return the callback that will create the popup.
        EventResult::with_cb(move |s| {
            // The callback will want to work with a fresh Rc
            let tree = Rc::clone(&tree);
            // We'll relativise the absolute position,
            // So that we are locked to the parent view.
            // A nice effect is that window resizes will keep both
            // layers together.
            let current_offset = s
                .screen()
                .layer_offset(LayerPosition::FromFront(0))
                .unwrap_or_else(Vec2::zero);
            let offset = offset.signed() - current_offset;
            // And finally, put the view in view!
            s.screen_mut()
                .add_layer_at(Position::parent(offset), MenuPopup::new(tree).focus(focus));
        })
    }

    // A popup view only does one thing: open the popup on Enter.
    fn on_event_popup(&mut self, event: Event) -> EventResult {
        match event {
            // TODO: add Left/Right support for quick-switch?
            Event::Key(Key::Enter) => self.open_popup(),
            Event::Mouse {
                event: MouseEvent::Release(MouseButton::Left),
                position,
                offset,
            } if position.fits_in_rect(offset, self.last_size) => self.open_popup(),
            _ => EventResult::Ignored,
        }
    }
}
#[allow(dead_code)]
impl CheckListView<String> {
    /// Convenient method to use the label as value.
    pub fn add_item_str<S: Into<String>>(&mut self, label: S, checked: bool) {
        let label = label.into();
        self.add_item(label.to_owned(), checked, label);
    }

    /// Chainable variant of add_item_str
    ///
    /// # Examples
    ///
    /// ```
    /// use cursive_core::views::CheckListView;
    ///
    /// let select_view = CheckListView::new()
    ///     .item_str("Paris")
    ///     .item_str("New York")
    ///     .item_str("Tokyo");
    /// ```
    #[must_use]
    pub fn item_str<S: Into<String>>(self, label: S) -> Self {
        self.with(|s| s.add_item_str(label, false))
    }

    /// Convenient method to use the label as value.
    pub fn insert_item_str<S>(&mut self, index: usize, label: S)
    where
        S: Into<String>,
    {
        let label = label.into();
        self.insert_item(index, label.to_owned(), false, label);
    }

    /// Adds all strings from an iterator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use cursive_core::views::CheckListView;
    /// let mut select_view = CheckListView::new();
    /// select_view.add_all_str(vec!["a", "b", "c"]);
    /// ```
    pub fn add_all_str<S, I>(&mut self, iter: I)
    where
        S: Into<String>,
        I: IntoIterator<Item = S>,
    {
        for s in iter {
            self.add_item_str(s, false);
        }
    }

    /// Adds all strings from an iterator.
    ///
    /// Chainable variant.
    ///
    /// # Examples
    ///
    /// ```
    /// use cursive_core::views::CheckListView;
    ///
    /// let text = "..."; // Maybe read some config file
    ///
    /// let select_view = CheckListView::new().with_all_str(text.lines());
    /// ```
    #[must_use]
    pub fn with_all_str<S, I>(self, iter: I) -> Self
    where
        S: Into<String>,
        I: IntoIterator<Item = S>,
    {
        self.with(|s| s.add_all_str(iter))
    }
}
#[allow(dead_code)]
impl<T: 'static> CheckListView<T>
where
    T: Ord,
{
    /// Sort the current items by their natural ordering.
    ///
    /// Note that this does not change the current focus index, which means that the current
    /// selection will likely be changed by the sorting.
    ///
    /// This sort is stable: items that are equal will not be reordered.
    pub fn sort(&mut self) {
        self.items.sort_by(|a, b| a.value.cmp(&b.value));
    }
}

impl<T: 'static> View for CheckListView<T> {
    fn draw(&self, printer: &Printer) {
        self.last_offset.set(printer.offset);

        if self.popup {
            // Popup-select only draw the active element.
            // We'll draw the full list in a popup if needed.
            let style = if !(self.enabled && printer.enabled) {
                ColorStyle::secondary()
            } else if printer.focused {
                ColorStyle::highlight()
            } else {
                ColorStyle::primary()
            };

            let x = match printer.size.x.checked_sub(1) {
                Some(x) => x,
                None => return,
            };

            printer.with_color(style, |printer| {
                // Prepare the entire background
                printer.print_hline::<XY<usize>>(XY::new(1, 0), x, " ");
                // Draw the borders
                printer.print::<XY<usize>>(XY::new(0, 0), "<");
                printer.print::<XY<usize>>(XY::new(x, 0), ">");

                if let Some(label) = self.items.get(self.focus()).map(|item| &item.label) {
                    // And center the text?
                    let offset = HAlign::Center.get_offset(label.width(), x + 1);

                    printer.print_styled(XY::new(offset, 0), SpannedStr::from(label));
                }
            });
        } else {
            // Non-popup mode: we always print the entire list.
            let h = self.items.len();
            let offset = self.align.v.get_offset(h, printer.size.y);
            let printer = &printer.offset((0, offset));

            for i in 0..self.len() {
                printer.offset::<XY<usize>>((0, i).into()).with_selection(
                    i == self.focus(),
                    |printer| {
                        if i != self.focus() && !(self.enabled && printer.enabled) {
                            printer.with_color(ColorStyle::secondary(), |printer| {
                                self.draw_item(printer, i)
                            });
                        } else {
                            self.draw_item(printer, i);
                        }
                    },
                );
            }
        }
    }

    fn required_size(&mut self, _: Vec2) -> Vec2 {
        if let Some(s) = self.last_required_size {
            return s;
        }
        // Items here are not compressible.
        // So no matter what the horizontal requirements are,
        // we'll still return our longest item.
        let w = self
            .items
            .iter()
            .map(|item| item.label.width() + 4)
            .max()
            .unwrap_or(1);
        let size = if self.popup {
            Vec2::new(w + 2, 1)
        } else {
            let h = self.items.len();

            Vec2::new(w, h)
        };
        self.last_required_size = Some(size);
        size
    }

    fn on_event(&mut self, event: Event) -> EventResult {
        if !self.enabled {
            return EventResult::Ignored;
        }

        if self.popup {
            self.on_event_popup(event)
        } else {
            self.on_event_regular(event)
        }
    }

    fn take_focus(&mut self, source: direction::Direction) -> Result<EventResult, CannotFocus> {
        (self.enabled && !self.items.is_empty())
            .then(|| {
                if !self.popup {
                    match source {
                        direction::Direction::Abs(direction::Absolute::Up) => {
                            self.focus.set(0);
                        }
                        direction::Direction::Abs(direction::Absolute::Down) => {
                            self.focus.set(self.items.len().saturating_sub(1));
                        }
                        _ => (),
                    }
                }
                EventResult::Consumed(None)
            })
            .ok_or(CannotFocus)
    }

    fn layout(&mut self, size: Vec2) {
        self.last_size = size;
    }

    fn important_area(&self, size: Vec2) -> Rect {
        self.selected_id()
            .map(|i| Rect::from_size((0, i), (size.x, 1)))
            .unwrap_or_else(|| Rect::from_size(Vec2::zero(), size))
    }
}

// We wrap each value in a `Rc` and add a label
struct Item<T> {
    label: StyledString,
    checked: bool,
    value: Rc<T>,
}

impl<T> Item<T> {
    fn new(label: StyledString, checked: bool, value: T) -> Self {
        let value = Rc::new(value);
        Item {
            label,
            checked,
            value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_view_sorting() {
        // We add items in no particular order, from going by their label.
        let mut view = CheckListView::new();
        view.add_item_str("Y", false);
        view.add_item_str("Z", false);
        view.add_item_str("X", false);

        // Then sorting the list...
        view.sort_by_label();

        // ... should observe the items in sorted order.
        // And focus is NOT changed by the sorting, so the first item is "X".
        assert_eq!(view.selection(), Some((false, Rc::new(String::from("X")))));
        view.on_event(Event::Key(Key::Down));
        assert_eq!(view.selection(), Some((false, Rc::new(String::from("Y")))));
        view.on_event(Event::Key(Key::Down));
        assert_eq!(view.selection(), Some((false, Rc::new(String::from("Z")))));
        view.on_event(Event::Key(Key::Down));
        assert_eq!(view.selection(), Some((false, Rc::new(String::from("Z")))));
    }

    #[test]
    fn select_view_sorting_with_comparator() {
        // We add items in no particular order, from going by their value.
        let mut view = CheckListView::new();
        view.add_item("Y", true, 2);
        view.add_item("Z", true, 1);
        view.add_item("X", true, 3);

        // Then sorting the list...
        view.sort_by(|a, b| a.cmp(b));

        // ... should observe the items in sorted order.
        // And focus is NOT changed by the sorting, so the first item is "X".
        assert_eq!(view.selection(), Some((true, Rc::new(1))));
        view.on_event(Event::Key(Key::Down));
        assert_eq!(view.selection(), Some((true, Rc::new(2))));
        view.on_event(Event::Key(Key::Down));
        assert_eq!(view.selection(), Some((true, Rc::new(3))));
        view.on_event(Event::Key(Key::Down));
        assert_eq!(view.selection(), Some((true, Rc::new(3))));
    }

    #[test]
    fn select_view_sorting_by_key() {
        // We add items in no particular order, from going by their key value.
        #[derive(Eq, PartialEq, Debug)]
        struct MyStruct {
            key: i32,
        }

        let mut view = CheckListView::new();
        view.add_item("Y", false, MyStruct { key: 2 });
        view.add_item("Z", true, MyStruct { key: 1 });
        view.add_item("X", false, MyStruct { key: 3 });

        // Then sorting the list...
        view.sort_by_key(|s| s.key);

        // ... should observe the items in sorted order.
        // And focus is NOT changed by the sorting, so the first item is "X".
        assert_eq!(view.selection(), Some((true, Rc::new(MyStruct { key: 1 }))));
        view.on_event(Event::Key(Key::Down));
        assert_eq!(
            view.selection(),
            Some((false, Rc::new(MyStruct { key: 2 })))
        );
        view.on_event(Event::Key(Key::Down));
        assert_eq!(
            view.selection(),
            Some((false, Rc::new(MyStruct { key: 3 })))
        );
        view.on_event(Event::Key(Key::Down));
        assert_eq!(
            view.selection(),
            Some((false, Rc::new(MyStruct { key: 3 })))
        );
    }

    #[test]
    fn select_view_sorting_orderable_items() {
        // We add items in no particular order, from going by their value.
        let mut view = CheckListView::new();
        view.add_item("Y", false, 2);
        view.add_item("Z", false, 1);
        view.add_item("X", false, 3);

        // Then sorting the list...
        view.sort();

        // ... should observe the items in sorted order.
        // And focus is NOT changed by the sorting, so the first item is "X".
        assert_eq!(view.selection(), Some((false, Rc::new(1))));
        view.on_event(Event::Key(Key::Down));
        assert_eq!(view.selection(), Some((false, Rc::new(2))));
        view.on_event(Event::Key(Key::Down));
        assert_eq!(view.selection(), Some((false, Rc::new(3))));
        view.on_event(Event::Key(Key::Down));
        assert_eq!(view.selection(), Some((false, Rc::new(3))));
    }
}
