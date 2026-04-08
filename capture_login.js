/*
 * capture_login.js - Automatic game credential capture
 *
 * Captures handshake.bin and login.bin during game login.
 * These files can be uploaded to the API for automated access.
 *
 * Usage:
 *   frida -U -f com.fun.lastwar.gp -l capture_login.js --no-pause
 *
 * Then log into your account in the game.
 */

'use strict';

console.log('\n' + '='.repeat(60));
console.log('[*] Last War Credential Capture Tool');
console.log('[*] Log into your account - credentials will be saved automatically');
console.log('='.repeat(60) + '\n');

var capturedHandshake = null;
var capturedLogin = null;
var packetCount = 0;
var loginComplete = false;

// Track connection state
var connectionEstablished = false;
var handshakeSent = false;

function toHex(ptr, len) {
    var result = "";
    try {
        var bytes = ptr.readByteArray(len);
        var arr = new Uint8Array(bytes);
        for (var i = 0; i < arr.length; i++) {
            result += ("0" + arr[i].toString(16)).slice(-2);
        }
    } catch(e) {
        result = "(error)";
    }
    return result;
}

function saveFile(path, data) {
    try {
        var file = new File(path, 'wb');
        file.write(data);
        file.close();
        console.log('[SAVED] ' + path + ' (' + data.byteLength + ' bytes)');
        return true;
    } catch(e) {
        console.log('[ERROR] Failed to save ' + path + ': ' + e);
        return false;
    }
}

// Hook send() to capture outgoing game packets
var libc = Process.getModuleByName("libc.so");
var sendAddr = libc.getExportByName("send");

if (sendAddr) {
    Interceptor.attach(sendAddr, {
        onEnter: function(args) {
            var fd = args[0].toInt32();
            var buf = args[1];
            var len = args[2].toInt32();

            // Only interested in packets > 500 bytes (handshake/login size)
            if (len < 500 || len > 10000) return;

            var header = toHex(buf, 4);
            packetCount++;

            // e406 = PC encrypted protocol
            // e405 = Mobile encrypted protocol
            if (header.startsWith("e406") || header.startsWith("e405")) {
                var packetData = buf.readByteArray(len);

                if (!handshakeSent) {
                    // First large packet = handshake
                    capturedHandshake = packetData;
                    handshakeSent = true;

                    console.log('\n' + '*'.repeat(60));
                    console.log('[CAPTURE] Handshake packet: ' + len + ' bytes');
                    console.log('[CAPTURE] Header: ' + header);
                    console.log('*'.repeat(60));

                    saveFile('/data/local/tmp/captured_handshake.bin', packetData);

                } else if (!loginComplete) {
                    // Second large packet = login
                    capturedLogin = packetData;
                    loginComplete = true;

                    console.log('\n' + '*'.repeat(60));
                    console.log('[CAPTURE] Login packet: ' + len + ' bytes');
                    console.log('[CAPTURE] Header: ' + header);
                    console.log('*'.repeat(60));

                    saveFile('/data/local/tmp/captured_login.bin', packetData);

                    console.log('\n' + '='.repeat(60));
                    console.log('[SUCCESS] Both packets captured!');
                    console.log('');
                    console.log('Files saved to:');
                    console.log('  /data/local/tmp/captured_handshake.bin');
                    console.log('  /data/local/tmp/captured_login.bin');
                    console.log('');
                    console.log('Pull files with:');
                    console.log('  adb pull /data/local/tmp/captured_handshake.bin ./');
                    console.log('  adb pull /data/local/tmp/captured_login.bin ./');
                    console.log('='.repeat(60) + '\n');
                }
            }

            // c408 = PC auth protocol (for email auth)
            if (header.startsWith("c408") || header.startsWith("e408")) {
                console.log('[AUTH] c408/e408 packet: ' + len + ' bytes (auth server traffic)');
            }
        }
    });
    console.log('[+] Hooked send() - waiting for login...\n');
}

// Also capture recv() to confirm successful login
var recvAddr = libc.getExportByName("recv");
if (recvAddr) {
    Interceptor.attach(recvAddr, {
        onEnter: function(args) {
            this.buf = args[1];
        },
        onLeave: function(retval) {
            var len = retval.toInt32();
            if (len > 5000 && loginComplete) {
                var header = toHex(this.buf, 4);
                if (header.startsWith("80") || header.startsWith("e4")) {
                    console.log('[RECV] Large response: ' + len + ' bytes - Login confirmed!');
                }
            }
        }
    });
}

// For combined handshake files (game_handshake_e406.bin format)
// Some games send both phases in sequence
var combinedBuffer = null;
var combinedSize = 0;

function checkForCombinedHandshake() {
    if (capturedHandshake && capturedLogin) {
        // Combine into single file for convenience
        var combined = new ArrayBuffer(capturedHandshake.byteLength + capturedLogin.byteLength);
        var view = new Uint8Array(combined);
        view.set(new Uint8Array(capturedHandshake), 0);
        view.set(new Uint8Array(capturedLogin), capturedHandshake.byteLength);

        saveFile('/data/local/tmp/captured_combined.bin', combined);
        console.log('[+] Combined file also saved: captured_combined.bin');
    }
}

// Check periodically if both are captured
setInterval(function() {
    if (capturedHandshake && capturedLogin && !combinedBuffer) {
        combinedBuffer = true;
        checkForCombinedHandshake();
    }
}, 2000);

console.log('[*] Ready! Now log into your game account...');
console.log('[*] The capture will happen automatically.\n');
