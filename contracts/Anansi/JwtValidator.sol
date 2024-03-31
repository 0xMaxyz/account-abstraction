// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./JsmnSolLib.sol";
import "./JwtTokenLib.sol";

library JwtValidator {
    using JsmnSolLib for bytes;

    error JsonParseFailed();
    error InvalidToken();

    function getToken(
        bytes memory json
    ) internal pure returns (JwtTokenLib.Claims memory) {
        bytes memory email;
        bytes memory aud;
        bytes memory nonce;
        bytes memory kid;

        (uint exitCode, JsmnSolLib.Token[] memory tokens, uint ntokens) = json
            .parse(30);
        if (exitCode != 0) {
            revert JsonParseFailed();
        }
        if (tokens[0].jsmnType != JsmnSolLib.JsmnType.OBJECT) {
            revert InvalidToken();
        }
        uint i = 1;
        bool found = false;
        while (i < ntokens) {
            if (tokens[i].jsmnType != JsmnSolLib.JsmnType.STRING) {
                revert InvalidToken();
            }
            bytes memory key = json.getBytes(tokens[i].start, tokens[i].end);
            if (key.strCompare("aud") == 0) {
                if (tokens[i + 1].jsmnType != JsmnSolLib.JsmnType.STRING) {
                    revert InvalidToken();
                }
                aud = json.getBytes(tokens[i + 1].start, tokens[i + 1].end);
                found = true;
            } else if (key.strCompare("email") == 0) {
                if (tokens[i + 1].jsmnType != JsmnSolLib.JsmnType.STRING) {
                    revert InvalidToken();
                }
                email = json.getBytes(tokens[i + 1].start, tokens[i + 1].end);
                found = true;
            } else if (key.strCompare("nonce") == 0) {
                if (tokens[i + 1].jsmnType != JsmnSolLib.JsmnType.STRING) {
                    revert InvalidToken();
                }
                nonce = json.getBytes(tokens[i + 1].start, tokens[i + 1].end);
                found = true;
            } else if (key.strCompare("kid") == 0) {
                if (tokens[i + 1].jsmnType != JsmnSolLib.JsmnType.STRING) {
                    revert InvalidToken();
                }
                kid = json.getBytes(tokens[i + 1].start, tokens[i + 1].end);
                found = true;
            }

            i += 2;
        }
        if (found) {
            return JwtTokenLib.Claims(aud, email, nonce, kid);
        }
        revert InvalidToken();
    }
}
