from urllib.parse import urlparse, urlunparse, urlencode, parse_qs, ParseResult
import requests

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
            raise ValueError(f"Error: {response.json()}")

    def generate_login_url(self, redirect_uri, scopes):
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

        generate_request_url = f"{self.base_url}/sso/generateURL?clientId={self.client_id}&redirectURI={urlencode(redirect_uri)}&scopes={stringified_scopes}"

        response = requests.get(generate_request_url, headers=self._build_auth_headers())
        self._valid_response_or_raise(response)

        return response.json()
    
    def authenticate(self, token: str) -> dict:
        if not token or len(token) == 0:
            raise ValueError("token is required")
        
        authenticate_request_url = f"{self.base_url}/sso/authenticate?clientId={self.client_id}"
        payload = {
            ssoToken: token,
            clientId: self.client_id
        }
        
        response = requests.post(authenticate_request_url, headers=self._build_auth_headers(), json=payload)
        self._valid_response_or_raise(response)

        return response.json()
