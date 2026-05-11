End-of-Life
========

This project will reach end-of-life on September 1st, 2022. On this date:

1. This repository will be [archived](https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories), making it read-only.
2. The Google Group will be locked, but will remain publicly searchable.
3. The project homepage, this README, and group will be updated to indicate that the project is end-of-life.

We will consider bug fixes from the community or support requests from existing customers up until this date.

Please make appropriate plans if you are using this library in production, e.g.:

* Dedicate personnel to maintaining your own internal copy of the library.
* Consider a commercial library such as the one offered by [Step Function I/O](https://stepfunc.io/products/libraries/dnp3/).

You can read about this decision in these blog posts:

* [OpenDNP3 Retrospective](https://stepfunc.io/blog/opendnp3-retrospective/)
* [DNP3 1.0.0 (Rust)](https://stepfunc.io/blog/dnp3_1_0_0/)

---
> **⚠️ This is a fork.** The upstream project reached end-of-life in 2022.
> This fork extends the library with **SAv2 and SAv5 (Secure Authentication)** support
> for the outstation role, targeting embedded Linux platforms (BeagleBone Black + Comms Cape).

SAv2 and SAv5 Outstation Support (this fork)
========

This fork adds a complete implementation of **DNP3 Secure Authentication Version 2 and Version 5**
(IEEE 1815-2010 and IEEE 1815-2012) for the outstation role. The implementation is
self-contained and does not break backward compatibility — SA is disabled by default
and activated via `OutstationParams`. The active version is selected at runtime via the `SAMode` enum.

### Architecture

The SA subsystem consists of four new modules:

| Module | File | Responsibility |
|---|---|---|
| `SAKeyManager` | `SAKeyManager.h/.cpp` | Key Status (g120v5), Key Change (g120v6), AES Key Unwrap (RFC 3394), HMAC-SHA256 confirmation |
| `SAChallenger` | `SAChallenger.h/.cpp` | Generates g120v1 Challenge, validates g120v2 Reply MAC |
| `SAResponder` | `SAResponder.h/.cpp` | Stores session keys (CDK/MDK) per user, computes HMAC for authenticated responses |
| `Group120Parser` / `Group120Builder` | `Group120Parser.h/.cpp`, `Group120Builder.h/.cpp` | Serializes/deserializes Group 120 Variations 1–6 |

`OutstationContext` intercepts critical function codes and initiates the
challenge-response exchange before execution per [IEEE 1815-2012](https://github.com/parumsancto/opendnp3/blob/release/DNP3-IEEE-Standard.pdf) Table 7-1.

### Configuration

#### C++

```cpp
// Select SA version: SAMode::NONE (default), SAMode::SAV2, SAMode::SAV5
config.outstation.params.saMode = SAMode::SAV5;

// SAv2: AES-128 Update Key — 16 bytes (128-bit)
config.outstation.params.saUpdateKey = {
    0x4D, 0x56, 0x4B, 0xEA, 0x57, 0x15, 0xDD, 0x96,
    0x59, 0xEF, 0x99, 0xA8, 0x95, 0xBB, 0x83, 0x0A,
    // remaining 16 bytes are unused for SAv2 (zero-padded)
};

// SAv5: AES-256 Update Key — 32 bytes (256-bit)
config.outstation.params.saUpdateKey = {
    0x4D, 0x56, 0x4B, 0xEA, 0x57, 0x15, 0xDD, 0x96,
    0x59, 0xEF, 0x99, 0xA8, 0x95, 0xBB, 0x83, 0x0A,
    0x4D, 0x56, 0x4B, 0xEA, 0x57, 0x15, 0xDD, 0x96,
    0x59, 0xEF, 0x99, 0xA8, 0x95, 0xBB, 0x83, 0x0A,
};
```

### Tested Interoperability

| SA Version | Master Software | Hardware |
|---|---|---|
| SAv5 | Zenon SCADA v15 by [COPA-DATA](https://www.copadata.com/) | BeagleBone Black + Comms Cape (Debian 12) |
| SAv2 | Geo SCADA Expert 2025 by Schneider Electric | BeagleBone Black + Comms Cape (Debian 12) |
| none | FreyrSCADA v21 | BeagleBone Black + Comms Cape (Debian 12) |

**MAC Algorithms**

| Algorithm | Status |
|---|---|
| HMAC-SHA-1 truncated to 10 bytes | ✅ Tested |
| HMAC-SHA-1 truncated to 8 bytes | ✅ Tested |
| HMAC-SHA-256 truncated to 8 bytes | ✅ Tested |
| HMAC-SHA-256 truncated to 16 bytes | ✅ Tested |
| AES-GMAC | ⚪ Not testable (not supported by zenon) |

**Key Wrap Algorithms**

| Algorithm  | Status |
|---|---|
| AES-128 Key Wrap (RFC 3394) | ✅ Tested |
| AES-256 Key Wrap (RFC 3394) | ✅ Tested |

**Modes**

| Feature | Status |
|---|---|
| Pre-challenge (normal) mode | ✅ Supported |
| Aggressive mode | ✅ Supported for SAv2 ❌ Not implemented for SAv5 |

### Dependencies

SA support requires **OpenSSL** (≥ 1.1.0) linked at build time (`libssl`, `libcrypto`).  
CMakeLists already includes OpenSSL detection for both Linux and Windows targets.

Overview
========

Opendnp3 is a portable, scalable, and rigorously tested implementation 
of the [DNP3](https//www.dnp.org) protocol stack written in C++11. The library 
is designed for high-performance applications like many concurrent TCP
sessions or huge device simulations. It also embeds with a small footprint on Linux.

Build status
============

| Branch       | Build | Code coverage | Quality |
| ------------ | ----- | ------------- | ------- |
| release-2.x  | [![CI 2.x](https://github.com/dnp3/opendnp3/workflows/CI/badge.svg?branch=release-2.x)](https://github.com/dnp3/opendnp3/actions?query=branch%3Arelease-2.x) | [![Codecov](https://codecov.io/gh/dnp3/opendnp3/branch/release-2.x/graph/badge.svg)](https://codecov.io/gh/dnp3/opendnp3/branch/release-2.x) | - |
| develop      | [![CI 2.x](https://github.com/dnp3/opendnp3/workflows/CI/badge.svg?branch=develop)](https://github.com/dnp3/opendnp3/actions?query=branch%3Adevelop) | [![Codecov](https://codecov.io/gh/dnp3/opendnp3/branch/develop/graph/badge.svg)](https://codecov.io/gh/dnp3/opendnp3/branch/develop) | [![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/dnp3/opendnp3.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/dnp3/opendnp3/context:cpp) |

Documentation
=============

The documentation can be found on the [project homepage](http://dnp3.github.io/#documentation).

If you want to help contribute to the official guide its in [this repo](https://github.com/dnp3/opendnp3-guide).			

License
=============

Licensed under the terms of the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0.html).

Copyright (c) 2010, 2011 Green Energy Corp

Copyright (c) 2013 - 2020 Step Function I/O LLC

Copyright (c) 2020 - 2022 Step Function I/O LLC

Copyright (c) 2010 - 2022 various contributors
