// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

library JwtTokenLib {
    struct Claims {
        bytes aud;
        bytes email;
        bytes nonce;
        bytes kid;
    }
}
