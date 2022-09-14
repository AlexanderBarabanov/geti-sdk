# Copyright (C) 2022 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions
# and limitations under the License.
import pytest

from sc_api_tools.http_session import SCSession
from sc_api_tools.http_session.sc_session import INITIAL_HEADERS
from sc_api_tools.platform_versions import SC11_VERSION, SC12_VERSION


class TestSCSession:
    def test_authenticate(self, fxt_sc_session: SCSession):
        """
        Test that the authenticated SCSession instance contains authentication cookies
        """
        fxt_sc_session.authenticate(verbose=False)

    def test_product_version(self, fxt_sc_session: SCSession):
        """
        Test that the 'version' attribute of the session is assigned a valid product
        version
        """
        known_versions = [SC11_VERSION, SC12_VERSION]
        version_matches = [
            fxt_sc_session.version >= version for version in known_versions
        ]
        assert sum(version_matches) >= 1

    @pytest.mark.vcr()
    def test_logout(self, fxt_sc_session: SCSession):
        """
        Test that logging out of the platform works, and clears all cookies and headers
        """
        fxt_sc_session.logout()
        assert len(fxt_sc_session.cookies) == 0
        assert len(fxt_sc_session.headers) == len(INITIAL_HEADERS)
        for key, value in fxt_sc_session._cookies.items():
            assert value is None
