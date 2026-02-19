This is a proof of concept, to support decryption of matrix messages, for an account with key backup and SSSS enabled, given the "Recovery Key".
This uses both [matrix-org/matrix-android-sdk2](https://github.com/matrix-org/matrix-android-sdk2), and [matrix-org/matrix-rust-components-kotlin](https://github.com/matrix-org/matrix-rust-components-kotlin/tree/main) directly to achieve its goals.

Further we plan on adding a PoC for creating the coresponding keys, and encrypting messages.

## Setup of SDKs

In [matrix-org/matrix-rust-components-kotlin](https://github.com/matrix-org/matrix-rust-components-kotlin/tree/main) there are scripts to generate the [matrix-sdk-crypto](https://mvnrepository.com/artifact/com.github.matrix-org.matrix-android-sdk/matrix-sdk-crypto) and [matrix-android-sdk](https://mvnrepository.com/artifact/com.github.matrix-org/matrix-android-sdk) _Android_ SDKs (`.aar`), which are used by [matrix-org/matrix-android-sdk2](https://github.com/matrix-org/matrix-android-sdk2).

Said scrips create shared libraries, and Kotlin bindings for those shared libraries using [UniFFI](https://mozilla.github.io/uniffi-rs/latest/), for various Android targets, and package them as [Android Archive](https://developer.android.com/studio/projects/android-library) files.
We initially attempted, to run those same scripts, but provide the [`x86_64-unkown-linux-gnu` target](https://doc.rust-lang.org/rustc/platform-support.html), but ran into issues.

So for the moment our approach for the libraries on a high level is
*  Extract the `classes.jar` Jars from the `sdk` and `crypto` AARs.
* Compile the shared libraries for a Linux target ourselves
  Of course as a todo we still plan on writing a script to simply generate the Kotlin bindings ourselves.

### Manual Library Steps

In this section we describe our approach for manually getting the libraries in more detail (for reproducibillty)

1. Fetch the latest [`matrix-android-sdk2`](https://mvnrepository.com/artifact/org.matrix.android/matrix-android-sdk2), place it in the `lib` folder, and check [via its dependencies](https://mvnrepository.com/artifact/org.matrix.android/matrix-android-sdk2/1.6.50/dependencies) with version of [org.matrix.rustcomponents](https://mvnrepository.com/artifact/org.matrix.rustcomponents):[crypto-android](https://mvnrepository.com/artifact/org.matrix.rustcomponents/crypto-android) it depends on (e.g. `26.1.28`)
2. Download said version of `matrix-crypto-android.aar`, unzip and copy the `classes.jar` file from the unzipped directory to the `lib` folder (renamed appropriately)
3. Identify the corresponding release in GitHub [matrix-org/matrix-rust-components-kotlin](https://github.com/matrix-org/matrix-rust-components-kotlin/releases) (e.g. [Release crypto-v26.1.28](https://github.com/matrix-org/matrix-rust-components-kotlin/releases/tag/crypto-v26.1.28)).
    1. This release will reference a commit in [matrix-org/matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk)  (e.g. [1fb2ca58433096178a1a438d052615ec568549f2](https://github.com/matrix-org/matrix-rust-sdk/tree/1fb2ca58433096178a1a438d052615ec568549f2)), check out said commit in `matrix-rust-sdk`
    2. Navigate to `matrix-rust-sdk/bindings/matrix-sdk-crypto-ffi/` and run `cargo build --release` there.  This will build the shared library for the current architecture.
    3. Copy the shared library in the resources folder (`cp ../../target/release/libmatrix_sdk_crypto_ffi.so ../../../matrix-kotlin-crypto/resources/`)
4. Identify required JNA (Java Native Access) version to use, and also include in `lib`. (This is necessary to load the shared library file from the resources)

So far it appears that besides these libraries we do not require any of the other dependencies of `matrix-android-sdk2` 