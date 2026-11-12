$ErrorActionPreference = "Stop"

$libDir = "c:\Sentient\target\gnullvm-libs"
if (-not (Test-Path "$libDir\libunwind.a")) {
    New-Item -ItemType Directory -Force $libDir | Out-Null
    Copy-Item "$env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\lib\self-contained\*" $libDir -Force
    Copy-Item "$env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnullvm\lib\self-contained\*" $libDir -Force
    Remove-Item "$libDir\libunwind.dll.a" -Force -ErrorAction SilentlyContinue
}

$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER = "$env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\rust-lld.exe"
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_RUSTFLAGS = "-C linker-flavor=ld.lld -C link-self-contained=no -C link-arg=$libDir\crt2.o -C link-arg=-L$libDir"

& "$env:USERPROFILE\.cargo\bin\cargo.exe" +stable-x86_64-pc-windows-gnu run --release --target x86_64-pc-windows-gnullvm --manifest-path "c:\Sentient\Cargo.toml"
