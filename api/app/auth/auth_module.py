from ..schemas import Token


def get_auth_module():
    return AuthModule(None)


class AuthModule:
    def __init__(self):
        pass

    def login_for_access_token(self, username, password) -> Token:
        return Token(access_token="", token_type="bearer", refresh_token="")

    def refresh_access_token(self, refresh_token) -> Token:
        return Token(access_token="", token_type="bearer", refresh_token="")

    def check_and_get_user_info(self, token):
        pass
