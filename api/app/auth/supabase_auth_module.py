import os

from supabase import Client, create_client

from app.auth.auth_module import AuthModule

from ..schemas import Token


class SupabaseAuthModule(AuthModule):
    def __init__(self):
        super().__init__()

        url = os.getenv("SUPABASE_URL")
        if url is None:
            raise Exception(f"Unsupported SUPABASE_URL: {url}")
        key = os.getenv("SUPABASE_ANON_KEY")
        if key is None:
            raise Exception(f"Unsupported SUPABASE_ANON_KEY: {key}")

        self.supabase: Client = create_client(url, key)

    def login_for_access_token(self, username, password) -> Token:
        payload = {
            "email": username,
            "password": password.get_secret_value(),
        }
        user_data = self.supabase.auth.sign_in_with_password(payload)
        session = user_data.dict().get("session")
        return Token(
            access_token=session.get("access_token"),
            token_type="bearer",
            refresh_token=session.get("refresh_token"),
        )

    def refresh_access_token(self, refresh_token) -> Token:
        return Token(access_token="", token_type="bearer", refresh_token="")

    def check_and_get_user_info(self, token):
        user_data = self.supabase.auth.get_user(token.credentials)
        user = user_data.dict().get("user")
        return user.get("id"), user.get("email")
