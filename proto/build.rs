// SPDX-License-Identifier: MIT
// Build script: compiles .proto files into Rust types using prost.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(
        &[
            "inference.proto",
            "filesystem.proto",
            "orchestrator.proto",
            "compositor.proto",
            "fortress.proto",
        ],
        &["."],
    )?;
    Ok(())
}
