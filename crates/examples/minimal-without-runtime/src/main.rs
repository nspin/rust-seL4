#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![feature(exclusive_wrapper)]
#![feature(ptr_to_from_bits)]

mod rt;

fn main(bootinfo: &sel4::BootInfo) -> ! {
    sel4::debug_println!("Hello, World!");

    let cnode = sel4::BootInfo::init_thread_cnode();

    let blueprint = sel4::ObjectBlueprint::Notification;
    let untyped = {
        let slot = bootinfo.untyped().start
            + bootinfo
                .untyped_list()
                .iter()
                .position(|desc| {
                    desc.isDevice == 0
                        && usize::from(desc.sizeBits) >= blueprint.physical_size_bits()
                })
                .unwrap();
        sel4::Untyped::from_bits(slot.try_into().unwrap())
    };

    let badge = 0x1337;

    let first_empty_slot = bootinfo.empty().start;
    let unbadged_notification_slot = first_empty_slot;
    let badged_notification_slot = first_empty_slot + 1;
    let unbadged_notification =
        sel4::Notification::from_bits(unbadged_notification_slot.try_into().unwrap());
    let badged_notification =
        sel4::Notification::from_bits(badged_notification_slot.try_into().unwrap());

    untyped
        .retype(
            &blueprint,
            &cnode.relative_self(),
            unbadged_notification_slot,
            1,
        )
        .unwrap();

    cnode
        .relative(badged_notification)
        .mint(
            &cnode.relative(unbadged_notification),
            sel4::CapRightsBuilder::none().write(true).build(),
            badge,
        )
        .unwrap();

    badged_notification.signal();
    let observed_badge = unbadged_notification.wait();

    sel4::debug_println!("badge: {:#x}", badge);
    assert_eq!(observed_badge, badge);

    sel4::BootInfo::init_thread_tcb().suspend().unwrap();
    unreachable!()
}
