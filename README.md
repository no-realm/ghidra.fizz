# ghidra.fizz

#### Ghidra: Fizz - Signature Maker Plugin

## Brief

This is a simple plugin which can create array of byte signatures for currently selected areas.

## Demo

![][ref-demo]

## Building

Run gradlew.bat

Gradle build outputs can be found in Fizz//dist//ghidra_A.B_PUBLIC_ZZZZYYXX_Fizz.zip

## Installing

1. Download the recent [release][ref-releases]
2. Extract Fizz folder from Zip into GHIDRA_INSTALL_DIR//Ghidra//Extensions//
3. Start Ghidra, a prompt of a new plugin has been found should show
4. Activate prompt and start using

## Hotkeys

- Create a RAW Signature
    - 1 + ALT
- Create Ghidra Signature
    - 2 + ALT
- Create Common Signature
    - 3 + ALT

## Todos

- [x] Added hotkeys on selection
- [x] Added copy on "OK" selection by default
- [x] Added back raw signature support
- [x] Reduced window output size
- [x] Cleaned source code
- [ ] A support into existing Ghidra Instruction Search Plugin

## Resolved Issues

- [x] Context Menu Duplicated hotkeys

## Developer

* ["quosego"][ref-self]

## License

This project is licensed under the [Apache License 2.0 (Apache-2.0)][ref-AP2]. See the [LICENSE.md][ref-lic-path] file for details.

[ref-demo]: ./doc/images/Q6KHnppHFG.gif
[ref-releases]: https://github.com/quosego/ghidra.fizz/releases
[ref-issue]: https://github.com/NationalSecurityAgency/ghidra/issues/13
[ref-self]: https://github.com/quosego
[ref-lic-path]: ./LICENSE.md
[ref-AP2]: https://tldrlegal.com/license/apache-license-2.0-(apache-2.0)
