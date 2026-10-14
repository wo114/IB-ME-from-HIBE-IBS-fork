# Public NIST ACVP sample vectors

Commit `975de31eb83d87039ec88934fdc47d8c312b892d` of https://github.com/usnistgov/ACVP-Server . The fixture contains only published TEST inputs, including published TEST secret keys. No project keys or runtime state. All 75 keyGen, 90 pure external sigGen, and 45 pure external sigVer sample cases are retained. HashML-DSA, internal/external-mu and other modes are outside this adapter. Expected large outputs are stored as SHA256. Raw source hashes are embedded in the fixture. This is sample-vector conformance, not NIST certification.

Compressed SHA256: `201573224ca3c999397e6650aba5791b4d72c19a2adac3a9640762162f76236b`; uncompressed SHA256: `b46455073a05f67c72a7e70c63176c6d73ec542cf9f0d6650a8c3e61eca542ef`.
