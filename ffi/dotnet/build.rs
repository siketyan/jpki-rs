fn main() {
    csbindgen::Builder::default()
        .input_extern_file("../generic/src/lib.rs")
        .csharp_dll_name("jpki")
        .csharp_namespace("Siketyan.Jpki.Native")
        .csharp_use_function_pointer(false)
        .generate_csharp_file("./Native/NativeMethods.g.cs")
        .unwrap();
}
