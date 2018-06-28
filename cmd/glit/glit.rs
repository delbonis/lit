extern crate iui;

use iui::prelude::*;
use iui::controls::{Button, Entry, Group, HorizontalBox, HorizontalSeparator, Label, Spinbox, VerticalBox};

// TODO Temp debug struct for testing
struct Balance {
	cointype: u32,
	sync_height: u64,
	txo_total: u64
}

impl Balance {
	fn new(ty: u32, height: u64, txos: u64) -> Balance {
		Balance {
			cointype: ty,
			sync_height: height,
			txo_total: txos
		}
	}
}

fn main() {

	let ui = UI::init().expect("Couldn't initialize libui!");

	let addr_bar = Entry::new(&ui);
	// TODO set_read_only
	let addr_button = Button::new(&ui, "New Address");
	// TODO New address button logic.

	let send_label = Label::new(&ui, "Send To:");
	let send_amt_label = Label::new(&ui, "Amount(sat):");
	let send_addr_box = Entry::new(&ui);
	let send_amt_box = Spinbox::new(&ui, 0, 100000000000);
	let send_status_label = Label::new(&ui, "");

	let mut bal_group = Group::new(&ui, "baLanCes");
	bal_group.set_title(&ui, " ");
	let mut bal_box = VerticalBox::new(&ui);
	bal_box.set_padded(&ui, true);

	let bals = vec![
		Balance::new(0, 1000, 5),
		Balance::new(1, 600, 2),
		Balance::new(10, 200, 8)
	];

	bal_box.append(&ui, Label::new(&ui, "Balances:"), LayoutStrategy::Compact);
	for b in bals {
		let l = format!("coin: {}, height: {}, bal: {}", b.cointype, b.sync_height, b.txo_total);
		let b_entry = Label::new(&ui, l.as_ref());
		bal_box.append(&ui, b_entry, LayoutStrategy::Compact);
	}

	bal_group.set_child(&ui, bal_box);

	let send_button = Button::new(&ui, "Send");
	let empty_label = Label::new(&ui, "");

	let mut send_hbox = HorizontalBox::new(&ui);
	send_hbox.set_padded(&ui, true);
	send_hbox.append(&ui, send_label, LayoutStrategy::Compact);
	send_hbox.append(&ui, send_addr_box, LayoutStrategy::Stretchy);
	send_hbox.append(&ui, send_amt_label, LayoutStrategy::Compact);
	send_hbox.append(&ui, send_amt_box, LayoutStrategy::Stretchy);

	let mut send_vbox = VerticalBox::new(&ui);
	send_vbox.set_padded(&ui, true);
	send_vbox.append(&ui, empty_label, LayoutStrategy::Compact);
	send_vbox.append(&ui, send_button, LayoutStrategy::Compact);

	// TODO Send button logic.
	// TODO Make this line not be here?
	//send_addr_box.set_title(&ui, "");

	let mut recv_hbox = HorizontalBox::new(&ui);
	recv_hbox.set_padded(&ui, true);
	recv_hbox.append(&ui, addr_bar, LayoutStrategy::Stretchy);
	recv_hbox.append(&ui, addr_button, LayoutStrategy::Compact);

	let mut window_vbox = VerticalBox::new(&ui);
	window_vbox.append(&ui, Label::new(&ui, ""), LayoutStrategy::Compact);
	window_vbox.append(&ui, Label::new(&ui, "My addresses:"), LayoutStrategy::Compact);
	window_vbox.append(&ui, recv_hbox, LayoutStrategy::Compact);
	window_vbox.append(&ui, HorizontalSeparator::new(&ui), LayoutStrategy::Compact);
	window_vbox.append(&ui, send_hbox, LayoutStrategy::Compact);
	window_vbox.append(&ui, send_vbox, LayoutStrategy::Compact);
	window_vbox.append(&ui, HorizontalSeparator::new(&ui), LayoutStrategy::Compact);
	window_vbox.append(&ui, send_status_label, LayoutStrategy::Compact);
	window_vbox.append(&ui, bal_group, LayoutStrategy::Compact);

	let mut window = Window::new(&ui, "Lit UI", 600, 400, WindowType::NoMenubar);
	window.set_child(&ui, window_vbox);
	window.show(&ui);
	ui.main();

}
