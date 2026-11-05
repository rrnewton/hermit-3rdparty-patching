#[used]
#[unsafe(link_section = ".preinit_array")]
static CAPTURE_STARTUP_STDIN: unsafe extern "C" fn() = hermit::app::capture_startup_stdin;

fn main() {
    if let Some(status) =
        hermit::app::executable_entry_with_backend::<hermit_patching::SabreAdapter>()
    {
        std::process::exit(status);
    }
    if module_path!().contains("::") {
        panic!("fbinit must be performed in the crate root on the main function");
    }
    unsafe { fbinit::perform_init_with_disable_signals(0x8002) };
    let _destroy_guard = unsafe { fbinit::DestroyGuard::new() };
    hermit::app::main_with_backend(hermit_patching::SabreAdapter);
}
