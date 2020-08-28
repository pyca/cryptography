from pluggy import HookimplMarker

import keyring


hookimpl = HookimplMarker("devpiclient")


@hookimpl()
def devpiclient_get_password(url, username):
    return keyring.get_password(url, username)
