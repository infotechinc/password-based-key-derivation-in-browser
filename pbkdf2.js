// Password Based Key Derivation with Web Cryptography API
//
// Copyright (c) 2015 Info Tech, Inc.
// Provided under the MIT license.
// See LICENSE file for details.

document.addEventListener("DOMContentLoaded", function() {
    "use strict";

    // Check that web crypto is even available
    if (!window.crypto || !window.crypto.subtle) {
        alert("Your browser does not support the Web Cryptography API! This page will not work.");
        return;
    }

    // Check that encoding API is also available
    if (!window.TextEncoder || !window.TextDecoder) {
        alert("Your browser does not support the Encoding API! This page will not work.");
        return;
    }

    document.getElementById("derive-key").addEventListener("click", deriveAKey);

    function deriveAKey() {
        var salt = "Pick anything you want. This isn't secret.";
        var iterations = 1000;
        var hash = document.getElementById("hash-name").value;

        var password = document.getElementById("password").value;

        // First, create a PBKDF2 "key" containing the password
        window.crypto.subtle.importKey(
            "raw",
            stringToArrayBuffer(password),
            {"name": "PBKDF2"},
            false,
            ["deriveKey"]).
        // Derive a key from the password
        then(function(baseKey){
            return window.crypto.subtle.deriveKey(
                {
                    "name": "PBKDF2",
                    "salt": stringToArrayBuffer(salt),
                    "iterations": iterations,
                    "hash": hash
                },
                baseKey,
                {"name": "AES-CBC", "length": 128}, // Key we want
                true,                               // Extrable
                ["encrypt", "decrypt"]              // For new key
                );
        }).
        // Export it so we can display it
        then(function(aesKey) {
            return window.crypto.subtle.exportKey("raw", aesKey);
        }).
        // Display it in hex format
        then(function(keyBytes) {
                var hexKey = arrayBufferToHexString(keyBytes);
                document.getElementById("aes-key").textContent = hexKey;
        }).
        catch(function(err) {
            alert("Key derivation failed: " + err.message);
        });
    }


    // Utility functions
    function stringToArrayBuffer(string) {
        var encoder = new TextEncoder("utf-8");
        return encoder.encode(string);
    }

    function arrayBufferToHexString(arrayBuffer) {
        var byteArray = new Uint8Array(arrayBuffer);
        var hexString = "";
        var nextHexByte;

        for (var i=0; i<byteArray.byteLength; i++) {
            nextHexByte = byteArray[i].toString(16);  // Integer to base 16
            if (nextHexByte.length < 2) {
                nextHexByte = "0" + nextHexByte;     // Otherwise 10 becomes just a instead of 0a
            }
            hexString += nextHexByte;
        }
        return hexString;
    }

});
