import base64
import logging

from social_core.backends.oauth import BaseOAuth2

LOG = logging.getLogger(__name__)

"""
see https://musicbrainz.org/doc/Development/OAuth2
"""


class MusicBrainzOAuth2(BaseOAuth2):
    """MusicBrainz OAuth2 authentication backend"""

    name = "musicbrainz"
    ID_KEY = "metabrainz_user_id"
    AUTHORIZATION_URL = "https://musicbrainz.org/oauth2/authorize"
    ACCESS_TOKEN_URL = "https://musicbrainz.org/oauth2/token"
    ACCESS_TOKEN_METHOD = "POST"
    SCOPE_SEPARATOR = " "
    REDIRECT_STATE = False
    EXTRA_DATA = [("refresh_token", "refresh_token")]

    DEFAULT_SCOPE = [
        "profile",  # View the user's public profile information (username, age, country, homepage).
        "email",  # View the user's email.
        "tag",  # View and modify the user's private tags.
        "rating",  # View and modify the user's private ratings.
        "collection",  # View and modify the user's private collections.
        "submit_isrc",  # Submit new ISRCs to the database.
        "submit_barcode",  # Submit barcodes to the database.
    ]

    def auth_headers(self):
        auth_str = "{0}:{1}".format(*self.get_key_and_secret())
        LOG.debug("auth_headers: %s", auth_str)
        b64_auth_str = base64.urlsafe_b64encode(auth_str.encode()).decode()
        return {"Authorization": "Basic {0}".format(b64_auth_str)}

    def get_user_details(self, response):
        """
        Return user details from musicbrainz account. The response is from https://musicbrainz.org/oauth2/userinfo?
        fro the user_data function below
        """
        get_user_names = self.get_user_names(response.get("sub"))
        fullname, first_name, last_name = get_user_names
        LOG.debug("get_user_details: %s", get_user_names)
        return {
            "username": response.get("id"),
            "email": response.get("email"),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

    def user_collection(self, access_token, *args, **kwargs):
        """Loads user collection data from service"""
        return self.get_json(
            "https://musicbrainz.org/ws/2/collection?fmt=json",
            headers={"Authorization": "Bearer {0}".format(access_token)},
        )

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        return self.get_json(
            "https://musicbrainz.org/oauth2/userinfo?access_token={access_token}".format(
                access_token=access_token
            )
        )

    def refresh_token_params(self, refresh_token, *args, **kwargs):
        return {"refresh_token": refresh_token, "grant_type": "refresh_token"}
