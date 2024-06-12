from urllib.parse import urlparse, urlunparse, urlencode, parse_qs, ParseResult, quote
import requests

class GenerateLoginUrlResponse:
    def __init__(self, success: bool, url: str):
        self.success = success
        self.url = url

    @staticmethod
    def from_json(json: dict):
        return GenerateLoginUrlResponse(json["success"], json["url"])

class AuthenticateResponse:
    def __init__(
            self, 
            success: bool, 
            id: str, 
            username: str, 
            avatar: str, 
            email: str, 
            key_2fa: str, 
            verified: bool,
            banned: bool, 
            role: dict, 
            permissions: list, 
            wallet: dict
        ):

        self.success = success
        self.id = id
        self.username = username
        self.avatar = avatar
        self.email = email
        self.key_2fa = key_2fa
        self.verified = verified
        self.banned = banned
        self.role = role
        self.permissions = permissions
        self.wallet = wallet

    @staticmethod
    def from_json(json: dict):
        return AuthenticateResponse(
            json["success"], 
            json["id"], 
            json["username"], 
            json["avatar"], 
            json["email"], 
            json["key_2fa"], 
            json["verified"], 
            json["banned"], 
            json["role"], 
            json["permissions"], 
            json["wallet"]
        )

class OgWallet:
    def __init__(self, base_url: str, client_id: str, client_secret:str):
        parsed_base_url = urlparse(base_url)
        if not all([parsed_base_url.scheme, parsed_base_url.netloc]):
            raise ValueError("Invalid base_url")
        
        if not client_id or len(client_id) == 0:
            raise ValueError("client_id is required")
        
        if not client_secret or len(client_secret) == 0:
            raise ValueError("client_secret is required")

        self.base_url = base_url if not base_url.endswith("/") else base_url[:-1]
        self.client_id = client_id
        self.client_secret = client_secret

    def _build_auth_headers(self) -> dict:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.client_secret}"
        }

    def _valid_response_or_raise(self, response) -> dict:
        if response.status_code < 200 or response.status_code > 299:
            raise RuntimeError(f"Error: {response.status_code} - {response.text}")

    def generate_login_url(self, redirect_uri: str, scopes: list) -> GenerateLoginUrlResponse:
        if not redirect_uri:
            raise ValueError("redirect_uri is required")
        
        parsed_redirect_uri = urlparse(redirect_uri)
        if not all([parsed_redirect_uri.scheme, parsed_redirect_uri.netloc]):
            raise ValueError("Invalid redirect_uri")

        if not scopes or len(scopes) == 0:
            raise ValueError("scopes is required")
        
        if not isinstance(scopes, list):
            raise ValueError("scopes must be a list")
    
        stringified_scopes = ",".join(scopes)

        generate_request_url = f"{self.base_url}/sso/generateURL?clientId={self.client_id}&redirectURI={quote(redirect_uri)}&scopes={stringified_scopes}"

        response = requests.get(generate_request_url, headers=self._build_auth_headers())
        self._valid_response_or_raise(response)

        return GenerateLoginUrlResponse.from_json(response.json())
    
    def authenticate(self, token: str) -> AuthenticateResponse:
        if not token or len(token) == 0:
            raise ValueError("token is required")
        
        authenticate_request_url = f"{self.base_url}/sso/authenticate?clientId={self.client_id}"
        payload = {
            "ssoToken": token,
            "clientId": self.client_id
        }
        
        response = requests.post(authenticate_request_url, headers=self._build_auth_headers(), json=payload)
        self._valid_response_or_raise(response)

        return AuthenticateResponse.from_json(response.json())
