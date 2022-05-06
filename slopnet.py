# -*- coding: utf-8 -*-
SCRIPT_NAME = 'slopnet'
SCRIPT_AUTHOR = 'hgc'
SCRIPT_VERSION = '1.0.0'
SCRIPT_LICENSE = 'licensehole larry'
SCRIPT_DESC = "Weechat's only diarhea-powered plugin"

import_ok = True

try:
    import weechat
except ImportError:
    print('This script must be run under WeeChat')
    print('You can obtain a copy of WeeChat, for free, at https://weechat.org')
    import_ok = False

weechat_version = 0

import shlex
import sys
import ed25519
import base64

def slopnet_cb(data, buffer, args):
    target = args.split(" ")[0]
    args = " ".join(args.split(" ")[1:])
    privkey = ed25519.SigningKey(base64.b64decode(weechat.config_get_plugin("privkeyb64")))

    weechat.command(buffer, target+ ": "+args)
    weechat.command(buffer, target + ": " +base64.b64encode(privkey.sign(args.encode())).decode())

    return weechat.WEECHAT_RC_OK

if __name__ == "__main__" and import_ok:
    if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "", ""):
        privkeyb64 = weechat.config_get_plugin("privkeyb64")
        if privkeyb64 == "":
            privkey, pubkey = ed25519.create_keypair()
            privkeyb64 = base64.b64encode(privkey.to_bytes()).decode()
            pubkeyb64 = base64.b64encode(pubkey.to_bytes()).decode()
            weechat.config_set_plugin("privkeyb64", privkeyb64)
        else:
            privkey = ed25519.SigningKey(base64.b64decode(privkeyb64))
            pubkey = privkey.get_verifying_key()
            pubkeyb64 = base64.b64encode(pubkey.to_bytes()).decode()

        weechat.prnt("", "Loaded key: " + pubkeyb64)

        weechat_version = weechat.info_get("version_number", "") or 0
        weechat.hook_command(
            "slopnet",
            "Eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "message", "",
            "",
            "slopnet_cb", ""
        )
