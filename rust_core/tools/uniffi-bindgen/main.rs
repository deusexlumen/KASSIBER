//! Thin wrapper around the pinned workspace uniffi version so the generated
//! bindings always match the `uniffi` crate the cdylib was built with.
fn main() {
    uniffi::uniffi_bindgen_main();
}
