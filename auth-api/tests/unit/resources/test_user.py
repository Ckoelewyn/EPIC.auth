# Copyright © 2024 Province of British Columbia
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Resource-level tests for the UserGroupName delete endpoint.

These tests focus on the DELETE /users/<user_id>/groups/<group_name> endpoint,
specifically that an empty request body no longer raises a 400 Bad Request when
parsing the optional JSON payload.
"""
from http import HTTPStatus
from unittest.mock import patch

import pytest
from flask import Flask, g
from flask_restx import Api

from auth_api.auth import jwt
from auth_api.resources.user import API as USER_API


@pytest.fixture()
def client():
    """Return a Flask test client with the user namespace mounted."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    api = Api(app)
    api.add_namespace(USER_API)
    return app.test_client()


@pytest.fixture()
def token_claims():
    """Supply an IDIR caller for the user endpoint tests."""
    return {"loginSource": "idir"}


@pytest.fixture(autouse=True)
def _mock_jwt_validation(token_claims):
    """Supply verified claims while exercising the caller check and resource."""

    def _fake_validation(*args, **kwargs):  # pylint: disable=unused-argument
        g.jwt_oidc_token_info = token_claims

    with patch.object(jwt, "_require_auth_validation", side_effect=_fake_validation):
        yield


class TestUserGroupNameDelete:
    """Tests for UserGroupName.delete payload handling."""

    @patch("auth_api.resources.user.UserService")
    def test_delete_user_group_without_body_returns_204(self, mock_service, client):
        """An empty body should parse as a None payload and return 204, not 400."""
        mock_service.delete_user_group.return_value = None

        response = client.delete(
            "/users/testuser/groups/SUBMIT",
            headers={"Authorization": "Bearer token"},
        )

        assert response.status_code == HTTPStatus.NO_CONTENT
        mock_service.delete_user_group.assert_called_once_with(
            "testuser", "SUBMIT", False, None
        )

    @patch("auth_api.resources.user.UserService")
    def test_delete_user_group_with_body_passes_payload(self, mock_service, client):
        """A JSON body should be forwarded to the service as the payload."""
        mock_service.delete_user_group.return_value = None

        response = client.delete(
            "/users/testuser/groups/EAO",
            json={"app_name": "SUBMIT"},
            headers={"Authorization": "Bearer token"},
        )

        assert response.status_code == HTTPStatus.NO_CONTENT
        mock_service.delete_user_group.assert_called_once_with(
            "testuser", "EAO", False, {"app_name": "SUBMIT"}
        )

    @patch("auth_api.resources.user.UserService")
    def test_delete_user_group_forwards_del_sub_group_mappings_flag(
        self, mock_service, client
    ):
        """The del_sub_group_mappings query flag should be forwarded as truthy."""
        mock_service.delete_user_group.return_value = None

        response = client.delete(
            "/users/testuser/groups/SUBMIT?del_sub_group_mappings=true",
            headers={"Authorization": "Bearer token"},
        )

        assert response.status_code == HTTPStatus.NO_CONTENT
        mock_service.delete_user_group.assert_called_once_with(
            "testuser", "SUBMIT", True, None
        )


@pytest.mark.parametrize(
    ("token_claims", "expected_status"),
    [
        ({"azp": "epic-centre", "preferred_username": " staff@IDIR "}, HTTPStatus.NO_CONTENT),
        ({"azp": "epic-compliance", "loginSource": " IDIR "}, HTTPStatus.NO_CONTENT),
        (
            {
                "azp": "submit-api-condition-client",
                "client_id": "submit-api-condition-client",
                "loginSource": "idir",
            },
            HTTPStatus.NO_CONTENT,
        ),
        (
            {"loginSource": "bceid", "preferred_username": "staff@idir"},
            HTTPStatus.FORBIDDEN,
        ),
        ({"client_id": "submit-api-condition-client"}, HTTPStatus.FORBIDDEN),
        ({}, HTTPStatus.FORBIDDEN),
    ],
)
@patch("auth_api.resources.user.UserService")
def test_user_group_delete_requires_idir(mock_service, client, expected_status):
    """Accept IDIR callers and reject other tokens before updating membership."""
    response = client.delete(
        "/users/testuser/groups/SUBMIT", headers={"Authorization": "Bearer token"}
    )

    assert response.status_code == expected_status
    if expected_status == HTTPStatus.FORBIDDEN:
        mock_service.delete_user_group.assert_not_called()
    else:
        mock_service.delete_user_group.assert_called_once()
