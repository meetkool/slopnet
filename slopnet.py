# -*- coding: utf-8 -*-
SCRIPT_NAME = 'slopnet'
SCRIPT_AUTHOR = 'hgc'
SCRIPT_VERSION = '1.0.1'
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

from nacl.encoding import Base64Encoder
from nacl.signing import SigningKey

def slopnet_cb(data, buffer, args):
    target, msg = args.split(':', 1)
    msg = msg.strip()
    privkey = SigningKey(weechat.config_get_plugin("privkeyb64").encode(),
            encoder=Base64Encoder)

    weechat.command(buffer, target+": "+msg)
    weechat.command(buffer, target+": "+privkey.sign(msg.encode(), encoder=Base64Encoder).signature.decode())

    return weechat.WEECHAT_RC_OK

if __name__ == "__main__" and import_ok:
    if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "", ""):
        privkeyb64 = weechat.config_get_plugin("privkeyb64")
        if privkeyb64 == "":
            privkey = SigningKey.generate()
            pubkey = privkey.verify_key
            privkeyb64 = privkey.encode(encoder=Base64Encoder).decode()
            pubkeyb64 = pubkey.encode(encoder=Base64Encoder).decode()
            weechat.config_set_plugin("privkeyb64", privkeyb64)
        else:
            privkey = SigningKey(privkeyb64.encode(), encoder=Base64Encoder)
            pubkey = privkey.verify_key
            pubkeyb64 = pubkey.encode(encoder=Base64Encoder).decode()

        weechat.prnt("", "Loaded key: " + pubkeyb64)

        weechat_version = weechat.info_get("version_number", "") or 0
        weechat.hook_command(
            "slopnet",
            "Eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "message", "",
            "",
            "slopnet_cb", ""
        )
