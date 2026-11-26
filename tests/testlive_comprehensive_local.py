#!/usr/bin/env python3
import os
import json
import uuid
import logging
import inspect
import subprocess
import unittest
import requests
import time
from io import BytesIO
import urllib3  # type: ignore
from datetime import datetime, timedelta, timezone
from typing import Union
from pymisp import PyMISP, MISPOrganisation, MISPUser, MISPRole, MISPSharingGroup, MISPEvent, MISPLog, MISPSighting, Distribution, ThreatLevel, Analysis, MISPEventReport, MISPServerError
from pymisp.tools import DomainIPObject
from pymisp.api import get_uuid_or_id_from_abstract_misp

logging.disable(logging.CRITICAL)
logger = logging.getLogger('pymisp')
urllib3.disable_warnings()

# Load access information for env variables
url = "http://" + os.environ["HOST"]
key = os.environ["AUTH"]


def create_simple_event() -> MISPEvent:
    caller_name = inspect.stack()[1].function
    event_uuid = str(uuid.uuid4())

    event = MISPEvent()
    event.uuid = event_uuid
    event.info = 'This is a super simple test ({}, {})'.format(event_uuid.split('-')[0], caller_name)
    event.distribution = Distribution.your_organisation_only
    event.threat_level_id = ThreatLevel.low
    event.analysis = Analysis.completed
    event.add_attribute('text', event_uuid)
    return event


def check_response(response):
    if isinstance(response, dict) and "errors" in response:
        raise Exception(response["errors"])
    return response


def request(pymisp: PyMISP, request_type: str, url: str, data: dict = {}) -> dict:
    response = pymisp._prepare_request(request_type, url, data)
    return pymisp._check_response(response)


def publish_immediately(pymisp: PyMISP, event: Union[MISPEvent, int, str, uuid.UUID], with_email: bool = False):
    event_id = get_uuid_or_id_from_abstract_misp(event)
    action = "alert" if with_email else "publish"
    return check_response(request(pymisp, 'POST', f'events/{action}/{event_id}/disable_background_processing:1'))


class MISPSetting:
    def __init__(self, admin_connector: PyMISP, new_setting: dict):
        self.admin_connector = admin_connector
        self.new_setting = new_setting

    def __enter__(self):
        self.original = self.__run("modify", json.dumps(self.new_setting).encode("utf-8"))
        # Try to reset config cache
        self.admin_connector.get_server_setting("MISP.live")

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__run("replace", self.original)
        # Try to reset config cache
        self.admin_connector.get_server_setting("MISP.live")

    @staticmethod
    def __run(command: str, data: bytes) -> bytes:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        r = subprocess.run(["php", dir_path + "/modify_config.php", command, data], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            raise Exception([r.returncode, r.stdout, r.stderr])
        return r.stdout


class TestComprehensive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.maxDiff = None
        # Connect as admin
        cls.admin_misp_connector = PyMISP(url, key, ssl=False, debug=False)
        cls.admin_misp_connector.set_server_setting('debug', 1, force=True)
        # Creates an org
        organisation = MISPOrganisation()
        organisation.name = 'Test Org'
        cls.test_org = cls.admin_misp_connector.add_organisation(organisation, pythonify=True)
        # Set the default role (id 3 on the VM)
        cls.admin_misp_connector.set_default_role(3)
        # Creates a user
        user = MISPUser()
        user.email = 'testusr@user.local'
        user.org_id = cls.test_org.id
        cls.test_usr = cls.admin_misp_connector.add_user(user, pythonify=True)
        cls.user_misp_connector = PyMISP(url, cls.test_usr.authkey, ssl=False, debug=True)

    @classmethod
    def tearDownClass(cls):
        # Delete user
        cls.admin_misp_connector.delete_user(cls.test_usr)
        # Delete org
        cls.admin_misp_connector.delete_organisation(cls.test_org)

    def setUp(self):
        self.user_misp_connector.global_pythonify = True
        self.admin_misp_connector.global_pythonify = True

    @unittest.skip("FIXME: That index will be empty.")
    def test_search_index(self):
        # Search all events
        index = self.user_misp_connector.search_index()
        self.assertGreater(len(index), 0)

        # Search published
        index_published = self.user_misp_connector.search_index(published=True)
        if len(index_published):
            print(index_published)
        self.assertEqual(len(index_published), 0, "No event should be published.")

        # Create test event
        event = create_simple_event()
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        # Search by org name
        index_org = self.user_misp_connector.search_index(org="Test Org")
        self.assertGreater(len(index_org), 0)

        # Search by org name with different case
        index_org_lower = self.user_misp_connector.search_index(org="test org")
        self.assertGreater(len(index_org_lower), 0)

        # Search by org uuid
        index_org_uuid = self.user_misp_connector.search_index(org=self.test_org.uuid)
        self.assertGreater(len(index_org_uuid), 0)

        # Search by org ID
        index_org_id = self.user_misp_connector.search_index(org=self.test_org.id)
        self.assertGreater(len(index_org_id), 0)

        self.assertEqual(len(index_org), len(index_org_lower))
        self.assertEqual(len(index_org), len(index_org_uuid))
        self.assertEqual(len(index_org), len(index_org_id))

        self.user_misp_connector.delete_event(event)

    def test_search_index_by_info(self):
        event = create_simple_event()
        event.info = uuid.uuid4()

        # No event should exist
        index = self.user_misp_connector.search_index(eventinfo=event.info)
        self.assertEqual(len(index), 0, "No event should exists")

        event = self.user_misp_connector.add_event(event)
        check_response(event)

        # One event should exist
        index = self.user_misp_connector.search_index(eventinfo=event.info)
        self.assertEqual(len(index), 1)
        self.assertEqual(index[0].uuid, event.uuid)

        index = self.user_misp_connector.search_index(eventinfo="!" + str(event.info))
        for index_event in index:
            self.assertNotEqual(event.uuid, index_event.uuid, index)

        self.user_misp_connector.delete_event(event)

    def test_search_index_by_all(self):
        event = create_simple_event()

        index = self.user_misp_connector.search_index(all=event.attributes[0].value)
        self.assertEqual(len(index), 0, "No event should exists")

        event = self.user_misp_connector.add_event(event)
        check_response(event)

        index = self.user_misp_connector.search_index(all=event.attributes[0].value)
        self.assertEqual(len(index), 1, "One event should exists")
        self.assertEqual(index[0].uuid, event.uuid)

        index = self.user_misp_connector.search_index(all=event.attributes[0].value.upper())
        self.assertEqual(len(index), 1, "One event should exists")
        self.assertEqual(index[0].uuid, event.uuid)

        self.user_misp_connector.delete_event(event)

    def test_search_index_by_attribute(self):
        event = create_simple_event()

        index = self.user_misp_connector.search_index(attribute=event.attributes[0].value)
        self.assertEqual(len(index), 0, "No event should exists")

        event = self.user_misp_connector.add_event(event)
        check_response(event)

        index = self.user_misp_connector.search_index(attribute=event.attributes[0].value)
        self.assertEqual(len(index), 1, "One event should exists")
        self.assertEqual(index[0].uuid, event.uuid)

        index = self.user_misp_connector.search_index(attribute=event.attributes[0].value.upper())
        self.assertEqual(len(index), 1, "One event should exists")
        self.assertEqual(index[0].uuid, event.uuid)

        self.user_misp_connector.delete_event(event)

    def test_search_index_by_tag(self):
        tags = self.user_misp_connector.search_tags("tlp:red", True)
        self.assertEqual(len(tags), 1, tags)  # tlp:red tag doesn't exists

        index = self.user_misp_connector.search_index(tags="tlp:red")
        self.assertEqual(len(index), 0, "No event should exists")

        index = self.user_misp_connector.search_index(tags=tags[0].id)
        self.assertEqual(len(index), 0, "No event should exists")

        event = create_simple_event()
        event.add_tag("tlp:red")
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        index = self.user_misp_connector.search_index(tags="tlp:red")
        self.assertEqual(len(index), 1, "One event should exists")

        index = self.user_misp_connector.search_index(tags="tlp:red|not_exists")
        self.assertEqual(len(index), 1, "One event should exists")

        index = self.user_misp_connector.search_index(tags=["tlp:red", "not_exists"])
        self.assertEqual(len(index), 1, "One event should exists")

        index = self.user_misp_connector.search_index(tags=tags[0].id)
        self.assertEqual(len(index), 1, "One event should exists")

        index = self.user_misp_connector.search_index(tags="!tlp:red")
        for index_event in index:
            self.assertNotEqual(event.uuid, index_event.uuid, index)

        index = self.user_misp_connector.search_index(tags="!" + str(tags[0].id))
        for index_event in index:
            self.assertNotEqual(event.uuid, index_event.uuid, index)

        self.user_misp_connector.delete_event(event)

    def test_search_index_by_email(self):
        index = self.user_misp_connector.search_index(email=self.test_usr.email)
        self.assertEqual(len(index), 0, index)

        event = create_simple_event()
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        index = self.user_misp_connector.search_index(email=self.test_usr.email)
        self.assertEqual(len(index), 1, "One event should exists")

        self.user_misp_connector.delete_event(event)

    def test_search_index_by_email_admin(self):
        index = self.admin_misp_connector.search_index(email="no_existing_exmail@example.com")
        self.assertEqual(len(index), 0, index)

        index = self.admin_misp_connector.search_index(email=self.test_usr.email)
        self.assertEqual(len(index), 0, index)

        event = create_simple_event()
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        index = self.admin_misp_connector.search_index(email=self.test_usr.email)
        self.assertEqual(len(index), 1, index)

        # Search by partial match
        index = self.admin_misp_connector.search_index(email="testusr@user")
        self.assertEqual(len(index), 1, index)

        self.user_misp_connector.delete_event(event)

    def test_search_index_by_eventid(self):
        # Search by non exists uuid
        index = self.admin_misp_connector.search_index(eventid=uuid.uuid4())
        self.assertEqual(len(index), 0, index)

        # Search by non exists id
        index = self.admin_misp_connector.search_index(eventid=9999)
        self.assertEqual(len(index), 0, index)

        event = create_simple_event()
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        index = self.admin_misp_connector.search_index(eventid=event.id)
        self.assertEqual(len(index), 1, index)

        index = self.admin_misp_connector.search_index(eventid=event.uuid)
        self.assertEqual(len(index), 1, index)

        self.user_misp_connector.delete_event(event)

    @unittest.skip("FIXME: That index will be empty.")
    def test_search_index_minimal(self):
        # pythonify is not supported for minimal results
        self.user_misp_connector.global_pythonify = False

        minimal = self.user_misp_connector.search_index(minimal=True)
        self.assertGreater(len(minimal), 0)
        minimal_event = minimal[0]
        self.assertIn("id", minimal_event)
        self.assertIn("timestamp", minimal_event)
        self.assertIn("sighting_timestamp", minimal_event)
        self.assertIn("published", minimal_event)
        self.assertIn("uuid", minimal_event)
        self.assertIn("orgc_uuid", minimal_event)
        for event in minimal:
            self.assertFalse(event["published"], "No event should be published.")

    def test_search_index_minimal_published(self):
        # pythonify is not supported for minimal results
        self.user_misp_connector.global_pythonify = False

        index = self.user_misp_connector.search_index(minimal=True, published=True)
        self.assertEqual(len(index), 0, "No event should be published.")

        index = self.user_misp_connector.search_index(minimal=True)
        not_published = self.user_misp_connector.search_index(minimal=True, published=0)
        both_2 = self.user_misp_connector.search_index(minimal=True, published=2)
        both_array = self.user_misp_connector.search_index(minimal=True, published=[0, 1])

        self.assertEqual(len(index), len(not_published))
        self.assertEqual(len(index), len(both_2))
        self.assertEqual(len(index), len(both_array))

    def test_search_index_minimal_by_org(self):
        # pythonify is not supported for minimal results
        self.user_misp_connector.global_pythonify = False

        # Create test event
        event = create_simple_event()
        event = self.user_misp_connector.add_event(event, pythonify=True)
        check_response(event)

        # Search by org name
        minimal_org = self.user_misp_connector.search_index(minimal=True, org="Test Org")
        self.assertGreater(len(minimal_org), 0)
        for event in minimal_org:
            self.assertEqual(event["orgc_uuid"], self.test_org.uuid)

        # Search by org name with different case
        minimal_org_lower = self.user_misp_connector.search_index(minimal=True, org="test org")
        self.assertGreater(len(minimal_org), 0)
        for event in minimal_org:
            self.assertEqual(event["orgc_uuid"], self.test_org.uuid)

        # Search by non exists org name
        minimal_org_non_existing = self.user_misp_connector.search_index(minimal=True, org="Test Org that doesn't exists")
        self.assertEqual(len(minimal_org_non_existing), 0)

        # Search by org uuid
        minimal_org_uuid = self.user_misp_connector.search_index(minimal=True, org=self.test_org.uuid)
        self.assertGreater(len(minimal_org), 0)
        for event in minimal_org:
            self.assertEqual(event["orgc_uuid"], self.test_org.uuid)

        # Search by non-existing uuid
        minimal_org_uuid_non_existing = self.user_misp_connector.search_index(minimal=True, org=uuid.uuid4())
        self.assertEqual(len(minimal_org_uuid_non_existing), 0)

        # Search by org ID
        minimal_org_id = self.user_misp_connector.search_index(minimal=True, org=self.test_org.id)
        self.assertGreater(len(minimal_org), 0)
        for event in minimal_org:
            self.assertEqual(event["orgc_uuid"], self.test_org.uuid)

        self.assertEqual(len(minimal_org), len(minimal_org_lower))
        self.assertEqual(len(minimal_org), len(minimal_org_uuid))
        self.assertEqual(len(minimal_org), len(minimal_org_id))

        # Search not by org
        minimal_org_not = self.user_misp_connector.search_index(minimal=True, org="!Test Org")
        for event in minimal_org_not:
            self.assertNotEqual(event["orgc_uuid"], self.test_org.uuid)
        minimal_org_lower_not = self.user_misp_connector.search_index(minimal=True, org="!test org")
        for event in minimal_org_lower_not:
            self.assertNotEqual(event["orgc_uuid"], self.test_org.uuid)
        minimal_org_uuid_not = self.user_misp_connector.search_index(minimal=True, org="!" + self.test_org.uuid)
        for event in minimal_org_uuid_not:
            self.assertNotEqual(event["orgc_uuid"], self.test_org.uuid)
        minimal_org_id_not = self.user_misp_connector.search_index(minimal=True, org="!" + str(self.test_org.id))
        for event in minimal_org_id_not:
            self.assertNotEqual(event["orgc_uuid"], self.test_org.uuid)

        self.assertEqual(len(minimal_org_not), len(minimal_org_lower_not))
        self.assertEqual(len(minimal_org_not), len(minimal_org_uuid_not))
        self.assertEqual(len(minimal_org_not), len(minimal_org_id_not))

        self.user_misp_connector.delete_event(event)

    def test_delete_event_blocklist(self):
        check_response(self.admin_misp_connector.set_server_setting('MISP.enableEventBlocklisting', 1))

        # Create test event
        event = create_simple_event()
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        # Delete event
        check_response(self.user_misp_connector.delete_event(event))

        check_response(self.admin_misp_connector.set_server_setting('MISP.enableEventBlocklisting', 0))

    def test_deleted_attributes(self):
        # Create test event
        event = create_simple_event()
        event.add_attribute('text', "deleted", deleted=True)
        event.add_attribute('text', "not-deleted")
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        # Not deleted
        fetched_event = self.user_misp_connector.get_event(event)
        check_response(fetched_event)
        self.assertEqual(len(fetched_event.attributes), 2, fetched_event)

        # Not deleted
        fetched_event = self.user_misp_connector.get_event(event, deleted=0)
        check_response(fetched_event)
        self.assertEqual(len(fetched_event.attributes), 2, fetched_event)

        # Include deleted
        fetched_event = self.user_misp_connector.get_event(event, deleted=1)
        check_response(fetched_event)
        self.assertEqual(len(fetched_event.attributes), 3, fetched_event)

        # Deleted only
        fetched_event = self.user_misp_connector.get_event(event, deleted=2)
        check_response(fetched_event)
        self.assertEqual(len(fetched_event.attributes), 1, fetched_event)

        # Both
        fetched_event = self.user_misp_connector.get_event(event, deleted=[0, 1])
        check_response(fetched_event)
        self.assertEqual(len(fetched_event.attributes), 3, fetched_event)

        check_response(self.user_misp_connector.delete_event(event))

    def test_view_event_exclude_local_tags(self):
        event = create_simple_event()
        event.add_tag({"name": "local", "local": 1})
        event.add_tag({"name": "global", "local": 0})
        event.attributes[0].add_tag({"name": "local", "local": 1})
        event.attributes[0].add_tag({"name": "global", "local": 0})

        event = self.admin_misp_connector.add_event(event)
        check_response(event)

        event_with_local_tags = self.admin_misp_connector.get_event(event)
        check_response(event_with_local_tags)
        self.assertEqual(len(event_with_local_tags.tags), 2)
        self.assertEqual(len(event_with_local_tags.attributes[0].tags), 2)

        event_without_local_tags = self.admin_misp_connector._check_response(self.admin_misp_connector._prepare_request('GET', f'events/view/{event.id}/excludeLocalTags:1'))
        check_response(event_without_local_tags)

        self.assertEqual(event_without_local_tags["Event"]["Tag"][0]["local"], 0, event_without_local_tags)
        self.assertEqual(event_without_local_tags["Event"]["Attribute"][0]["Tag"][0]["local"], 0, event_without_local_tags)

        check_response(self.admin_misp_connector.delete_event(event))

    def test_publish_alert_filter(self):
        first = create_simple_event()
        first.add_tag('test_publish_filter')
        first.threat_level_id = ThreatLevel.medium

        second = create_simple_event()
        second.add_tag('test_publish_filter')
        second.threat_level_id = ThreatLevel.high

        third = create_simple_event()
        third.add_tag('test_publish_filter')
        third.threat_level_id = ThreatLevel.low

        four = create_simple_event()
        four.threat_level_id = ThreatLevel.high

        try:
            # Enable autoalert on admin
            self.admin_misp_connector._current_user.autoalert = True
            check_response(self.admin_misp_connector.update_user(self.admin_misp_connector._current_user))

            # Set publish_alert_filter tag to `test_publish_filter`
            setting_value = {'AND': {'Tag.name': 'test_publish_filter', 'ThreatLevel.name': ['High', 'Medium']}}
            check_response(self.admin_misp_connector.set_user_setting('publish_alert_filter', setting_value))

            # Add  events
            first = check_response(self.admin_misp_connector.add_event(first))
            second = check_response(self.admin_misp_connector.add_event(second))
            third = check_response(self.admin_misp_connector.add_event(third))
            four = check_response(self.admin_misp_connector.add_event(four))

            # Publish events
            for event in (first, second, third, four):
                publish_immediately(self.admin_misp_connector, event, with_email=True)

            # Email notification should be send just to first event
            mail_logs = self.admin_misp_connector.search_logs(model='User', action='email')
            log_titles = [log.title for log in mail_logs]

            self.assertIn('Email  to admin@admin.test sent, titled "[ORGNAME MISP] Event ' + str(first.id) + ' - Medium - TLP:AMBER".', log_titles)
            self.assertIn('Email  to admin@admin.test sent, titled "[ORGNAME MISP] Event ' + str(second.id) + ' - High - TLP:AMBER".', log_titles)
            self.assertNotIn('Email  to admin@admin.test sent, titled "[ORGNAME MISP] Event ' + str(third.id) + ' - Low - TLP:AMBER".', log_titles)
            self.assertNotIn('Email  to admin@admin.test sent, titled "[ORGNAME MISP] Event ' + str(four.id) + ' - High - TLP:AMBER".', log_titles)

        finally:
            # Disable autoalert
            self.admin_misp_connector._current_user.autoalert = False
            check_response(self.admin_misp_connector.update_user(self.admin_misp_connector._current_user))
            # Delete filter
            self.admin_misp_connector.delete_user_setting('publish_alert_filter')
            # Delete events
            for event in (first, second, third, four):
                check_response(self.admin_misp_connector.delete_event(event))

    def test_correlations(self):
        first = create_simple_event()
        first.add_attribute("ip-src", "10.0.0.1")
        first = check_response(self.admin_misp_connector.add_event(first))

        second = create_simple_event()
        second.add_attribute("ip-src", "10.0.0.1")
        second = check_response(self.admin_misp_connector.add_event(second))

        # Reload to get event data with related events
        first = check_response(self.admin_misp_connector.get_event(first))

        try:
            self.assertEqual(1, len(first.RelatedEvent), first.RelatedEvent)
            self.assertEqual(1, len(second.RelatedEvent), second.RelatedEvent)
        except:
            raise
        finally:
            # Delete events
            for event in (first, second):
                check_response(self.admin_misp_connector.delete_event(event))

    def test_correlations_object(self):
        first = create_simple_event()
        dom_ip_obj = DomainIPObject({'ip': ['10.0.0.1']})
        first.add_object(dom_ip_obj)
        first = check_response(self.admin_misp_connector.add_event(first))

        second = create_simple_event()
        dom_ip_obj = DomainIPObject({'ip': ['10.0.0.1']})
        second.add_object(dom_ip_obj)
        second = check_response(self.admin_misp_connector.add_event(second))

        # Reload to get event data with related events
        first = check_response(self.admin_misp_connector.get_event(first))

        try:
            self.assertEqual(1, len(first.RelatedEvent), first.RelatedEvent)
            self.assertEqual(1, len(second.RelatedEvent), second.RelatedEvent)
        except:
            raise
        finally:
            # Delete events
            for event in (first, second):
                check_response(self.admin_misp_connector.delete_event(event))

    def test_correlations_noacl(self):
        with MISPSetting(self.admin_misp_connector, {"MISP.correlation_engine": "NoAcl"}):
            self.test_correlations()
            self.test_correlations_object()
            self.test_recorrelate()

    def test_advanced_correlations(self):
        with MISPSetting(self.admin_misp_connector, {"MISP.enable_advanced_correlations": True}):
            first = create_simple_event()
            first.add_attribute("ip-src", "10.0.0.0/8")
            first = check_response(self.admin_misp_connector.add_event(first))

            second = create_simple_event()
            second.add_attribute("ip-src", "10.0.0.1")
            second = check_response(self.admin_misp_connector.add_event(second))

            # Reload to get event data with related events
            first = check_response(self.admin_misp_connector.get_event(first))

            try:
                self.assertEqual(1, len(first.RelatedEvent), first.RelatedEvent)
                self.assertEqual(1, len(second.RelatedEvent), second.RelatedEvent)
            except:
                raise
            finally:
                # Delete events
                for event in (first, second):
                    check_response(self.admin_misp_connector.delete_event(event))

    def test_remove_orphaned_correlations(self):
        result = self.admin_misp_connector._check_response(self.admin_misp_connector._prepare_request('POST', 'servers/removeOrphanedCorrelations'))
        check_response(result)
        self.assertIn("message", result)

    def test_recorrelate(self):
        first = create_simple_event()
        dom_ip_obj = DomainIPObject({'ip': ['10.0.0.1']})
        first.add_object(dom_ip_obj)
        first = check_response(self.admin_misp_connector.add_event(first))

        second = create_simple_event()
        dom_ip_obj = DomainIPObject({'ip': ['10.0.0.1']})
        second.add_object(dom_ip_obj)
        second = check_response(self.admin_misp_connector.add_event(second))

        check_response(self.admin_misp_connector.set_server_setting('MISP.background_jobs', 0, force=True))
        result = self.admin_misp_connector._check_response(self.admin_misp_connector._prepare_request('POST', 'attributes/generateCorrelation'))
        check_response(result)
        self.assertIn("message", result)
        check_response(self.admin_misp_connector.set_server_setting('MISP.background_jobs', 1, force=True))

        first = check_response(self.admin_misp_connector.get_event(first))
        second = check_response(self.admin_misp_connector.get_event(second))

        try:
            self.assertEqual(1, len(first.RelatedEvent), first.RelatedEvent)
            self.assertEqual(1, len(second.RelatedEvent), second.RelatedEvent)
        except:
            raise
        finally:
            # Delete events
            for event in (first, second):
                check_response(self.admin_misp_connector.delete_event(event))

    def test_restsearch_event_by_tags(self):
        first = create_simple_event()
        first.add_tag('test_search_tag')
        first.add_tag('test_search_tag_third')
        first.add_tag('test_search_tag_both')
        first = self.admin_misp_connector.add_event(first)
        check_response(first)

        second = create_simple_event()
        second.add_tag('test_search_tag_second')
        second.add_tag('test_search_tag_both')
        second = self.admin_misp_connector.add_event(second)
        check_response(second)

        search_result = self.admin_misp_connector.search(metadata=True, tags=["non_exists_tag"])
        self.assertEqual(0, len(search_result))

        search_result = self.admin_misp_connector.search(metadata=True, tags=["test_search_tag"])
        self.assertEqual(1, len(search_result))
        self.assertEqual(first.id, search_result[0].id)

        search_result = self.admin_misp_connector.search(metadata=True, tags="test_search_tag")
        self.assertEqual(1, len(search_result))
        self.assertEqual(first.id, search_result[0].id)

        # Like style match
        search_result = self.admin_misp_connector.search(metadata=True, tags=["test_search_tag%"])
        self.assertEqual(2, len(search_result))

        search_result = self.admin_misp_connector.search(metadata=True, tags=["test_search_tag_second"])
        self.assertEqual(1, len(search_result))
        self.assertEqual(second.id, search_result[0].id)

        search_result = self.admin_misp_connector.search(metadata=True, tags=["!test_search_tag"])
        search_result_ids = [event.id for event in search_result]
        self.assertNotIn(first.id, search_result_ids)
        self.assertIn(second.id, search_result_ids)

        search_result = self.admin_misp_connector.search(metadata=True, tags={"NOT": ["test_search_tag"]})
        search_result_ids = [event.id for event in search_result]
        self.assertNotIn(first.id, search_result_ids)
        self.assertIn(second.id, search_result_ids)

        search_result = self.admin_misp_connector.search(metadata=True, tags={"NOT": "test_search_tag"})
        search_result_ids = [event.id for event in search_result]
        self.assertNotIn(first.id, search_result_ids)
        self.assertIn(second.id, search_result_ids)

        search_result = self.admin_misp_connector.search(metadata=True, tags=["test_search_tag", "test_search_tag_second"])
        self.assertEqual(2, len(search_result))

        search_result = self.admin_misp_connector.search(metadata=True, tags={"AND": ["test_search_tag", "test_search_tag_third"]})
        self.assertEqual(1, len(search_result))
        self.assertEqual(first.id, search_result[0].id)

        search_result = self.admin_misp_connector.search(metadata=True, tags={"AND": ["test_search_tag", "test_search_tag_both"]})
        search_result_ids = [event.id for event in search_result]
        self.assertEqual(1, len(search_result_ids))
        self.assertIn(first.id, search_result_ids)

        check_response(self.admin_misp_connector.delete_event(first))
        check_response(self.admin_misp_connector.delete_event(second))

    def test_log_new_audit(self):
        check_response(self.admin_misp_connector.set_server_setting('MISP.log_new_audit', 1, force=True))

        event = create_simple_event()
        event.add_tag('test_log_new_audit_tag')
        event = check_response(self.admin_misp_connector.add_event(event))

        check_response(self.admin_misp_connector.delete_event(event))

        check_response(self.admin_misp_connector.set_server_setting('MISP.log_new_audit', 0, force=True))

        audit_logs = self.admin_misp_connector._check_response(self.admin_misp_connector._prepare_request('GET', 'admin/audit_logs/index'))
        check_response(audit_logs)
        self.assertGreater(len(audit_logs), 0)

    def test_add_tag_to_attachment(self):
        event = create_simple_event()
        with open(__file__, 'rb') as f:
            event.add_attribute('attachment', value='testfile.py', data=BytesIO(f.read()))
        event = check_response(self.admin_misp_connector.add_event(event))

        attribute_uuids = [attribute.uuid for attribute in event.attributes if attribute.type == 'attachment']
        self.assertEqual(1, len(attribute_uuids))

        check_response(self.admin_misp_connector.tag(attribute_uuids[0], 'generic_tag_test'))

        check_response(self.admin_misp_connector.delete_event(event))

    def test_add_duplicate_tags(self):
        event = create_simple_event()
        event = check_response(self.admin_misp_connector.add_event(event))

        # Just first tag should be added
        check_response(self.admin_misp_connector.tag(event.uuid, 'generic_tag_test', local=True))
        check_response(self.admin_misp_connector.tag(event.uuid, 'generic_tag_test', local=False))

        fetched_event = check_response(self.admin_misp_connector.get_event(event))
        self.assertEqual(1, len(fetched_event.tags), fetched_event.tags)
        self.assertTrue(fetched_event.tags[0].local, fetched_event.tags[0])

    def test_export(self):
        event = create_simple_event()
        event.add_attribute("ip-src", "1.2.4.5", to_ids=True)
        event = check_response(self.admin_misp_connector.add_event(event))

        result = self._search_event({'returnFormat': "yara", 'eventid': event.id, "published": [0, 1]})
        self.assertTrue("1.2.4.5" in result, result)
        self.assertTrue("GENERATED" in result, result)
        self.assertTrue("AS-IS" in result, result)

        result = self._search_event({'returnFormat': "yara-json", 'eventid': event.id, "published": [0, 1]})
        self.assertIn("generated", result)
        self.assertEqual(len(result["generated"]), 1, result)
        self.assertIn("as-is", result)

        # RPZ
        result = self._search_event({'returnFormat': "rpz", 'eventid': event.id, "published": [0, 1]})
        self.assertTrue("32.5.4.2.1" in result, result)

        result = self._search_attribute({'returnFormat': "rpz", 'eventid': event.id, "published": [0, 1]})
        self.assertTrue("32.5.4.2.1" in result, result)

        check_response(self.admin_misp_connector.delete_event(event))

    def test_event_report_empty_name(self):
        event = create_simple_event()
        new_event_report = MISPEventReport()
        new_event_report.name = ""
        new_event_report.content = "# Example report markdown"
        new_event_report.distribution = 5  # Inherit

        try:
            event = check_response(self.user_misp_connector.add_event(event))
            new_event_report = self.user_misp_connector.add_event_report(event.id, new_event_report)
            self.assertIn("errors", new_event_report)
        finally:
            self.user_misp_connector.delete_event(event)

    def test_new_audit(self):
        with MISPSetting(self.admin_misp_connector, {"MISP.log_new_audit": True}):
            event = create_simple_event()
            event = check_response(self.user_misp_connector.add_event(event))
            self.user_misp_connector.delete_event(event)

    def test_csp_report(self):
        response = self.admin_misp_connector._prepare_request('POST', 'servers/cspReport', data={
            "csp-report": {
                "test": "test",
            }
        })
        self.assertEqual(204, response.status_code)

    def test_redacted_setting(self):
        response = self.admin_misp_connector.get_server_setting('Security.salt')
        self.assertEqual(403, response["errors"][0])

        response = self.admin_misp_connector._prepare_request('GET', 'servers/serverSettingsEdit/Security.salt')
        response = self.admin_misp_connector._check_response(response)
        self.assertEqual(403, response["errors"][0])

    def test_custom_warninglist(self):
        warninglist = {
            "Warninglist": {
                "name": "Test",
                "description": "Test",
                "type": "cidr",
                "category": "false_positive",
                "matching_attributes": ["ip-src", "ip-dst"],
                "entries": "1.2.3.4",
            }
        }
        wl = request(self.admin_misp_connector, 'POST', 'warninglists/add', data=warninglist)
        check_response(wl)

        exported = request(self.admin_misp_connector, 'GET', f'warninglists/export/{wl["Warninglist"]["id"]}')
        self.assertIn('name', exported)
        self.assertEqual('Test', exported['name'])

        check_response(self.admin_misp_connector.enable_warninglist(wl["Warninglist"]["id"]))

        response = self.admin_misp_connector.values_in_warninglist("1.2.3.4")
        self.assertEqual(wl["Warninglist"]["id"], response["1.2.3.4"][0]["id"])

        warninglist["Warninglist"]["entries"] = "1.2.3.4\n2.3.4.5"
        response = request(self.admin_misp_connector, 'POST', f'warninglists/edit/{wl["Warninglist"]["id"]}', data=warninglist)
        check_response(response)

        response = self.admin_misp_connector.values_in_warninglist("2.3.4.5")
        self.assertEqual(wl["Warninglist"]["id"], response["2.3.4.5"][0]["id"])

        warninglist["Warninglist"]["entries"] = "2.3.4.5"
        response = request(self.admin_misp_connector, 'POST', f'warninglists/edit/{wl["Warninglist"]["id"]}', data=warninglist)
        check_response(response)

        response = self.admin_misp_connector.values_in_warninglist("1.2.3.4")
        self.assertEqual(0, len(response))

        response = self.admin_misp_connector.values_in_warninglist("2.3.4.5")
        self.assertEqual(wl["Warninglist"]["id"], response["2.3.4.5"][0]["id"])

        check_response(self.admin_misp_connector.disable_warninglist(wl["Warninglist"]["id"]))

        response = self.admin_misp_connector.values_in_warninglist("2.3.4.5")
        self.assertEqual(0, len(response))

        # Update by importing
        response = request(self.admin_misp_connector, 'POST', f'warninglists/import', exported)
        check_response(response)

        response = request(self.admin_misp_connector, 'POST', f'warninglists/delete/{wl["Warninglist"]["id"]}')
        check_response(response)

        # Create new warninglist by importing under different name
        exported["name"] = "Test2"
        response = request(self.admin_misp_connector, 'POST', f'warninglists/import', exported)
        check_response(response)

        response = request(self.admin_misp_connector, 'POST', f'warninglists/delete/{response["id"]}')
        check_response(response)

    def test_protected_event(self):
        event = create_simple_event()
        event = check_response(self.admin_misp_connector.add_event(event))

        response = request(self.admin_misp_connector, 'POST', f'events/protect/{event.id}')
        check_response(response)

        response = request(self.admin_misp_connector, 'POST', f'events/unprotect/{event.uuid}')
        check_response(response)

        response = request(self.admin_misp_connector, 'POST', f'events/protect/{event.uuid}')
        check_response(response)

        response = self.admin_misp_connector._prepare_request('GET', f'events/view/{event.id}')
        self.assertIn('x-pgp-signature', response.headers)
        self.assertTrue(len(response.headers['x-pgp-signature']) > 0, response.headers['x-pgp-signature'])

    def test_get_all_apis(self):
        response = self.admin_misp_connector._prepare_request('GET', 'api/getAllApis.json')
        self.assertEqual(200, response.status_code, response)
        response.json()

    def test_taxonomy_export(self):
        response = self.admin_misp_connector._prepare_request('GET', 'taxonomies/export/1')
        self.assertEqual(200, response.status_code, response)
        response.json()

    def test_etag(self):
        headers = {
            'Authorization': key.strip(),
            'Accept': 'application/json',
            'User-Agent': 'PyMISP',
            'If-None-Match': '',
        }
        response = requests.get(self.admin_misp_connector.root_url + '/attributes/describeTypes.json', headers=headers)
        self.assertEqual(200, response.status_code)
        self.assertIn('Etag', response.headers)
        self.assertTrue(len(response.headers['Etag']) > 0, response.headers['Etag'])

        headers['If-None-Match'] = response.headers['Etag']
        response = requests.get(self.admin_misp_connector.root_url + '/attributes/describeTypes.json', headers=headers)
        self.assertEqual(304, response.status_code, response.headers)

    def test_event_alert_default_enabled(self):
        user = MISPUser()
        user.email = 'testusr_alert_disabled@user.local'
        user.org_id = self.test_org.id

        created_user = check_response(self.admin_misp_connector.add_user(user))
        self.assertFalse(created_user.autoalert, created_user)
        self.admin_misp_connector.delete_user(created_user)

        with MISPSetting(self.admin_misp_connector, {"MISP.default_publish_alert": True}):
            user = MISPUser()
            user.email = 'testusr_alert_enabled@user.local'
            user.org_id = self.test_org.id

            created_user = check_response(self.admin_misp_connector.add_user(user))
            self.assertTrue(created_user.autoalert, created_user)
            self.admin_misp_connector.delete_user(created_user)

    def test_attribute_search(self):
        request(self.admin_misp_connector, "GET", "/attributes/search/value:8.8.8.8.json")

    def test_search_snort_suricata(self):
        event = create_simple_event()
        event.add_attribute('ip-src', '8.8.8.8', to_ids=True)
        event.add_attribute('snort', 'alert tcp 192.168.1.0/24 any -> 131.171.127.1 25 (content: "hacking"; msg: "malicious packet"; sid:2000001;)', to_ids=True)
        # Snort rule without msg, test for #9515
        event.add_attribute('snort', 'alert tcp 192.168.1.0/24 any -> 131.171.127.1 25 (content: "hacking"; sid:2000001;)', to_ids=True)
        event = check_response(self.user_misp_connector.add_event(event))

        publish_immediately(self.admin_misp_connector, event)

        snort = self._search_event({'returnFormat': 'snort', 'eventid': event.id})
        self.assertIsInstance(snort, str)
        self.assertIn('8.8.8.8', snort)

        suricata = self._search_event({'returnFormat': 'suricata', 'eventid': event.id})
        self.assertIsInstance(suricata, str)
        self.assertIn('8.8.8.8', suricata)

        self.admin_misp_connector.delete_event(event)

    def test_restsearch_composite_attribute(self):
        event = create_simple_event()
        attribute_1 = event.add_attribute('ip-src|port', '10.0.0.1|8080')
        attribute_2 = event.add_attribute('ip-src|port', '10.0.0.2|8080')
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        search_result = self._search_attribute({'value': '10.0.0.1', 'eventid': event.id})
        self.assertEqual(search_result['Attribute'][0]['uuid'], attribute_1.uuid)
        self.assertEqual(len(search_result['Attribute']), 1)

        search_result = self._search_attribute({'value': '8080', 'eventid': event.id})
        self.assertEqual(len(search_result['Attribute']), 2)

        search_result = self._search_attribute({'value1': '10.0.0.1', 'eventid': event.id})
        self.assertEqual(len(search_result['Attribute']), 1)
        self.assertEqual(search_result['Attribute'][0]['uuid'], attribute_1.uuid)

        search_result = self._search_attribute({'value1': '10.0.0.2', 'eventid': event.id})
        self.assertEqual(len(search_result['Attribute']), 1)
        self.assertEqual(search_result['Attribute'][0]['uuid'], attribute_2.uuid)

        search_result = self._search_attribute({'value2': '8080', 'eventid': event.id})
        self.assertEqual(len(search_result['Attribute']), 2)

        search_result = self._search_attribute({'value1': '10.0.0.1', 'value2': '8080', 'eventid': event.id})
        self.assertEqual(len(search_result['Attribute']), 1)
        self.assertEqual(search_result['Attribute'][0]['uuid'], attribute_1.uuid)

        self.admin_misp_connector.delete_event(event)

    def test_restsearch_sightings(self):
        # Create test event
        event = create_simple_event()
        event = self.admin_misp_connector.add_event(event)
        check_response(event)

        # Add sighting
        sighting = MISPSighting()
        sighting.value = 'test'
        sighting.source = 'Testcases'
        sighting.type = '1'

        response = self.admin_misp_connector.add_sighting(sighting, event.attributes[0])
        check_response(response)
        self.assertEqual(response.source, 'Testcases')

        # Try to find sighting by event UUID, this is the same type of request when doing sync
        search_result = self._search_sighting('event', {
            'returnFormat': 'json',
            'last': 0,
            'includeUuid': True,
            'uuid': [event.uuid],
        })
        self.assertEqual(len(search_result), 1, search_result)
        sighting = search_result[0]["Sighting"]
        self.assertIn("attribute_uuid", sighting)
        self.assertIn("event_uuid", sighting)
        self.assertEqual(sighting["event_uuid"], event.uuid, search_result)

        self.admin_misp_connector.delete_event(event)

    def test_restsearch_extend_event(self):
        # parent_event
        # ├── event_1son
        # └── event_2son
        #      └── event_2son_1son
        try:
            event = create_simple_event()
            event = self.admin_misp_connector.add_event(event)
            check_response(event)

            event_1son = create_simple_event()
            event_1son.extends_uuid=event.uuid
            event_1son = self.admin_misp_connector.add_event(event_1son)
            check_response(event_1son)

            event_2son = create_simple_event()
            event_2son.extends_uuid=event.uuid
            event_2son = self.admin_misp_connector.add_event(event_2son)
            check_response(event_2son)

            event_2son_1son = create_simple_event()
            event_2son_1son.extends_uuid=event_2son.uuid
            event_2son_1son = self.admin_misp_connector.add_event(event_2son_1son)
            check_response(event_2son_1son)

            search_result = self._search_event({
                'returnFormat': 'json',
                'is_extended': 1,
                'eventid': [event.id, event_1son.id, event_2son.id, event_2son_1son.id]
            })

            self.assertEqual(len(search_result), 2, search_result)
            self.assertEqual(search_result[0]['Event']['extends_uuid'], '')
            self.assertEqual(search_result[1]['Event']['extends_uuid'], event.uuid)

            search_result = self._search_event({
                'returnFormat': 'json',
                'is_extended': 0,
                'eventid': [event.id, event_1son.id, event_2son.id, event_2son_1son.id]
            })
            self.assertEqual(len(search_result), 2, search_result)
            self.assertEqual(search_result[0]['Event']['extends_uuid'], event.uuid)
            self.assertEqual(search_result[1]['Event']['extends_uuid'], event_2son.uuid)

            search_result = self._search_event({
                'returnFormat': 'json',
                'is_extension': [1],
                'eventid': [event.id, event_1son.id, event_2son.id, event_2son_1son.id]
            })
            self.assertEqual(len(search_result),3, search_result)
            self.assertEqual(search_result[0]['Event']['extends_uuid'], event.uuid)
            self.assertEqual(search_result[1]['Event']['extends_uuid'], event.uuid)
            self.assertEqual(search_result[2]['Event']['extends_uuid'], event_2son.uuid)

            search_result = self._search_event({
                'returnFormat': 'json',
                'is_extension': False,
                'eventid': [event.id, event_1son.id, event_2son.id, event_2son_1son.id]
            })
            self.assertEqual(len(search_result), 1, search_result)
            self.assertEqual(search_result[0]['Event']['extends_uuid'], '')
        finally:
            # Delete events
            self.admin_misp_connector.delete_event(event)
            self.admin_misp_connector.delete_event(event_1son)
            self.admin_misp_connector.delete_event(event_2son)
            self.admin_misp_connector.delete_event(event_2son_1son)


    def test_warninglists_category(self):
        try:
            #Create a test event
            event = create_simple_event()
            event = self.admin_misp_connector.add_event(event)
            check_response(event)
            #Create a false positive warninglist
            warninglist1 = {
                "Warninglist": {
                    "name": "My false positive",
                    "description": "some description",
                    "type": "cidr",
                    "category": "false_positive",
                    "matching_attributes": ["ip-src", "ip-dst"],
                    "entries": "1.1.1.1\n2.2.2.2"
                }
            }
            wl1 = request(self.admin_misp_connector, 'POST', 'warninglists/add', data=warninglist1)
            check_response(wl1)
            check_response(self.admin_misp_connector.enable_warninglist(wl1["Warninglist"]["id"]))


            #Create a known identifier warninglist
            warninglist2 = {
                "Warninglist": {
                    "name": "My known identifier",
                    "description": "some description",
                    "type": "cidr",
                    "category": "known",
                    "matching_attributes": ["ip-src", "ip-dst"],
                    "entries": "3.3.3.3\n4.4.4.4"
                }
            }
            wl2 = request(self.admin_misp_connector, 'POST', 'warninglists/add', data=warninglist2)
            check_response(wl2)
            check_response(self.admin_misp_connector.enable_warninglist(wl2["Warninglist"]["id"]))


            #Adding attributes to the event
            event.add_attribute("ip-src", "1.1.1.1", to_ids=True)
            event.add_attribute("ip-src", "2.2.2.2", to_ids=False)
            event.add_attribute("ip-src", "3.3.3.3", to_ids=True)
            event.add_attribute("ip-src", "4.4.4.4", to_ids=True)
            event = self.admin_misp_connector.update_event(event)
            check_response(event)

            search_result = self._search_event({
                'returnFormat': 'json',
                'eventid': event.id,
                'includeWarninglistHits' : True
            })
            attributes = search_result[0]['Event']['Attribute']

            warning_hits = [attr for attr in attributes if 'warnings' in attr and attr['warnings']]
            self.assertEqual(len(warning_hits), 3, f"Expected 3 attributes with warninglist hits, got {len(warning_hits)}")

            #Check the warninglist category
            expected_categories = {
                "1.1.1.1": "false_positive",
                "3.3.3.3": "known",
                "4.4.4.4": "known"
            }
            for attr in warning_hits:
                val = attr['value']
                if val in expected_categories:
                    for warning in attr['warnings']:
                        if warning['warninglist_name'] in ["My false positive", "My known identifier"]:
                            self.assertEqual(warning['warninglist_category'], expected_categories[val], f"Expected category '{expected_categories[val]}' for {val}, got {warning['warninglist_category']}")

        finally:
            #Delete the event
            self.admin_misp_connector.delete_event(event)
            #Delete the warninglists
            wl1 = request(self.admin_misp_connector, 'POST', f'warninglists/delete/{wl1["Warninglist"]["id"]}')
            wl2 = request(self.admin_misp_connector, 'POST', f'warninglists/delete/{wl2["Warninglist"]["id"]}')





    def _search_event(self, query: dict):
        response = self.admin_misp_connector._prepare_request('POST', 'events/restSearch', data=query)
        response = self.admin_misp_connector._check_response(response)
        check_response(response)
        return response

    def _search_attribute(self, query: dict):
        response = self.admin_misp_connector._prepare_request('POST', 'attributes/restSearch', data=query)
        response = self.admin_misp_connector._check_response(response)
        check_response(response)
        return response

    def _search_sighting(self, context: str, query: dict):
        response = self.admin_misp_connector._prepare_request('POST', f'sightings/restSearch/{context}', data=query)
        response = self.admin_misp_connector._check_response(response)
        check_response(response)
        return response


class TestLastPwChange(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin_misp_connector = PyMISP(url, key)

        organisation = MISPOrganisation()
        organisation.name = 'Test org for last pw change tests'
        cls.test_org = cls.admin_misp_connector.add_organisation(organisation, pythonify=True)
        check_response(cls.test_org)
        cls.test_org_id = cls.test_org.id

    @classmethod
    def tearDownClass(cls) -> None:
        cls.admin_misp_connector.delete_organisation(cls.test_org)

    def setUp(self) -> None:
        self.admin_misp_connector = type(self).admin_misp_connector

        # Create a user
        user = MISPUser()
        user.email = 'testusr_last_pw_change@user' + gen_random_id() + '.local'  # make name always unique
        user.org_id = type(self).test_org_id
        user.role_id = 3  # User role
        user.password = str(uuid.uuid4())
        self.test_usr = self.admin_misp_connector.add_user(user, pythonify=True)
        check_response(self.test_usr)
        self.test_usr_misp_connector = PyMISP(url, self.test_usr.authkey)

    def tearDown(self) -> None:
        # Delete Authkey and user
        body = {
            "authkey_start": self.test_usr.authkey[0:4],
            "authkey_end": self.test_usr.authkey[-4:],
            "User.id": self.test_usr.id
        }
        auth_key = type(self).admin_misp_connector.direct_call('auth_keys', body)
        check_response(auth_key)
        if len(auth_key) == 1 and "AuthKey" in auth_key[0]:
            type(self).admin_misp_connector.direct_call(f'auth_keys/delete/{auth_key[0]["AuthKey"]["id"]}', {})

        type(self).admin_misp_connector.delete_user(self.test_usr)

    def test_new_user_last_pw_change_is_date_created(self):
        self.assertEqual(self.test_usr.last_pw_change, self.test_usr.date_created)
        time.sleep(1)

    def test_admin_edit_password_updates_last_pw_change(self):
        old_last_pw_change = self.test_usr.last_pw_change

        # edit user password
        self.test_usr.password = uuid.uuid4()
        time_just_before_update = datetime.now()
        self.updated_test_usr = self.admin_misp_connector.update_user(self.test_usr, pythonify=True)
        time_just_after_update = datetime.now()
        check_response(self.updated_test_usr)

        self.check_last_pw_change_timestamp(old_last_pw_change, time_just_before_update, time_just_after_update)
        time.sleep(1)

    def test_user_change_password_updates_last_pw_change(self):
        old_last_pw_change = self.test_usr.last_pw_change

        # edit user password
        time_just_before_update = datetime.now()
        change_password_result = self.test_usr_misp_connector.change_user_password(uuid.uuid4())
        time_just_after_update = datetime.now()
        check_response(change_password_result)
        self.updated_test_usr = self.test_usr_misp_connector.get_user(pythonify=True)
        check_response(self.updated_test_usr)

        self.check_last_pw_change_timestamp(old_last_pw_change, time_just_before_update, time_just_after_update)
        time.sleep(1)

    def test_reset_user_password_updates_last_pw_change(self):
        old_last_pw_change = self.test_usr.last_pw_change

        # reset user password
        time_just_before_update = datetime.now()
        self.admin_misp_connector.direct_call(f'users/initiatePasswordReset/{self.test_usr.id}', {})
        time.sleep(1)
        time_just_after_update = datetime.now()
        self.updated_test_usr = self.test_usr_misp_connector.get_user(pythonify=True)
        check_response(self.updated_test_usr)

        self.check_last_pw_change_timestamp(old_last_pw_change, time_just_before_update, time_just_after_update)
        time.sleep(1)

    def last_pw_change_almost_equal_to_date_modified(self):
        date_modified = datetime.fromtimestamp(int(self.updated_test_usr.date_modified))
        last_pw_change = datetime.fromtimestamp(int(self.updated_test_usr.last_pw_change))
        return date_modified - last_pw_change < timedelta(milliseconds=5)

    def last_pw_change_time_is_in_expected_range(self, time_just_before_update, time_just_after_update):
        timediff_last_pw_change_now = datetime.fromtimestamp(int(self.updated_test_usr.last_pw_change)) - time_just_before_update
        max_accepted_timediff = time_just_after_update - time_just_before_update
        return timediff_last_pw_change_now <= max_accepted_timediff

    def check_last_pw_change_timestamp(self, old_last_pw_change, time_just_before_update, time_just_after_update):
        # check if new last_pw_change timestamp looks okay, starting with fact that it should be newer than previous one
        # self.assertGreater(self.updated_test_usr.last_pw_change, old_last_pw_change)

        # last pw change should be set to timestamp sometime between time_just_before_update and time_just_after_update
        self.assertTrue(self.last_pw_change_time_is_in_expected_range(time_just_before_update, time_just_after_update))

        # last_pw_change should be relatively close to date_modified
        self.assertTrue(self.last_pw_change_almost_equal_to_date_modified())


class TestStixImportClusterTags(unittest.TestCase):
    """A STIX 2 import attaches the cluster tag of every Galaxy Cluster of the
    document that exists after the import and that the importing user can
    see."""

    STOCK_USER_ROLE_ID = 3
    MANAGE_ORG_EVENTS = 2
    ATTACH_CLUSTER_COLOUR = '#0088cc'

    @classmethod
    def setUpClass(cls):
        cls.admin = PyMISP(url, key, ssl=False, debug=False)
        cls.marker = 'stix-cluster-tags-' + gen_random_id()
        organisation = MISPOrganisation()
        organisation.name = 'Test org for STIX cluster tags ' + gen_random_id()
        cls.test_org = check_response(
            cls.admin.add_organisation(organisation, pythonify=True))
        cls.created_users = []
        cls.created_roles = []
        cls.created_events = set()

        stock_user_role = request(
            cls.admin, 'GET', f'roles/view/{cls.STOCK_USER_ROLE_ID}')['Role']
        assert stock_user_role['perm_galaxy_editor'], stock_user_role
        assert stock_user_role['perm_tagger'], stock_user_role
        assert not stock_user_role['perm_tag_editor'], stock_user_role
        cls.stock_user = cls._add_user(cls.STOCK_USER_ROLE_ID)
        cls.tag_editor = cls._add_user(cls._add_role(
            'tag editor', perm_tagger=True, perm_tag_editor=True,
            perm_galaxy_editor=False))
        cls.galaxy_editor = cls._add_user(cls._add_role(
            'galaxy editor', perm_tagger=False, perm_tag_editor=False,
            perm_galaxy_editor=True))

        # External STIX 2.1 malware share one instance-wide galaxy, which
        # another org may have hidden; it stays visible to all after the tests
        cls._upload(
            cls.admin, cls._external_bundle(cls._malware()),
            cluster_distribution=Distribution.all_communities.value)

        default_clusters = cls._clusters(
            type='threat-actor', default=1, limit=1)
        assert default_clusters, (
            'the instance needs the default threat-actor galaxy')
        cls.default_cluster = default_clusters[0]

    @classmethod
    def tearDownClass(cls):
        for event_id in cls.created_events:
            cls.admin.delete_event(event_id)
        for cluster in cls._clusters(value=cls.marker + '%'):
            cls.admin.delete_galaxy_cluster(cluster['id'], hard=True)
        for user in cls.created_users:
            cls.admin.delete_user(user)
        for role_id in cls.created_roles:
            request(cls.admin, 'POST', f'admin/roles/delete/{role_id}')
        cls.admin.delete_organisation(cls.test_org)

    @classmethod
    def _add_role(cls, name: str, **flags) -> int:
        role = request(cls.admin, 'POST', 'admin/roles/add', {
            'name': f'{cls.marker} {name}',
            'permission': cls.MANAGE_ORG_EVENTS, 'perm_auth': True, **flags,
        })['Role']
        for flag, value in flags.items():
            assert bool(role[flag]) == value, (flag, role)
        cls.created_roles.append(role['id'])
        return int(role['id'])

    @classmethod
    def _add_user(cls, role_id) -> PyMISP:
        user = MISPUser()
        user.email = f'{cls.marker}-{gen_random_id()}@user.local'
        user.org_id = cls.test_org.id
        user.role_id = role_id
        user = check_response(cls.admin.add_user(user, pythonify=True))
        cls.created_users.append(user)
        return PyMISP(url, user.authkey, ssl=False, debug=False)

    @classmethod
    def _clusters(cls, **filters) -> list:
        found = request(cls.admin, 'POST', 'galaxy_clusters/restSearch',
                        {'returnFormat': 'json', **filters})
        if isinstance(found, dict):
            found = found.get('response', [])
        return [entry['GalaxyCluster'] for entry in found]

    @staticmethod
    def _stix_object(stix_type: str, **properties) -> dict:
        now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        return {
            'type': stix_type, 'spec_version': '2.1',
            'id': f'{stix_type}--{uuid.uuid4()}',
            'created': now, 'modified': now, **properties,
        }

    @classmethod
    def _malware(cls) -> dict:
        return cls._stix_object(
            'malware', name=f'{cls.marker}-{gen_random_id()}',
            is_family=False)

    @classmethod
    def _external_bundle(cls, *stix_objects: dict) -> dict:
        report = cls._stix_object(
            'report', name=f'{cls.marker} report',
            report_types=['threat-report'],
            object_refs=[stix_object['id'] for stix_object in stix_objects])
        report['published'] = report['created']
        return {
            'type': 'bundle', 'id': f'bundle--{uuid.uuid4()}',
            'objects': [report, *stix_objects],
        }

    @classmethod
    def _upload(cls, connector: PyMISP, bundle: dict, **url_params) -> dict:
        response = connector._prepare_request(
            'POST', 'events/upload_stix/2', data=bundle, kw_params=url_params)
        event = check_response(connector._check_json_response(response))
        cls.created_events.add(event['Event']['id'])
        return cls.admin.get_event(
            event['Event']['id'], pythonify=False)['Event']

    def _only_cluster(self, value: str) -> dict:
        clusters = self._clusters(value=value)
        self.assertEqual(1, len(clusters), clusters)
        return clusters[0]

    @staticmethod
    def _cluster_tag_names(event: dict, galaxy_type: str = '') -> set:
        prefix = 'misp-galaxy:' + (f'{galaxy_type}=' if galaxy_type else '')
        return {tag['name'] for tag in event.get('Tag', [])
                if tag['name'].startswith(prefix)}

    def _stored_clusters(self, cluster_uuid: str) -> list:
        columns = ('id', 'uuid', 'value', 'tag_name', 'version', 'default',
                   'locked', 'distribution', 'org_id', 'orgc_id', 'galaxy_id',
                   'description')
        return [{column: cluster[column] for column in columns}
                for cluster in self._clusters(uuid=cluster_uuid)]

    def _custom_cluster(self, connector: PyMISP) -> dict:
        value = f'{self.marker}-{gen_random_id()}'
        check_response(connector.add_galaxy_cluster(
            self.default_cluster['galaxy_id'], {
                'value': value, 'description': value,
                'distribution': Distribution.your_organisation_only.value,
            }))
        return self._only_cluster(value)

    def _assert_round_trip_attaches_the_stored_cluster_tag(
            self, connector: PyMISP, cluster: dict):
        event = check_response(
            connector.add_event(create_simple_event(), pythonify=True))
        self.created_events.add(event.id)
        check_response(connector.attach_galaxy_cluster(event, cluster['id']))
        bundle = check_response(connector.search(
            controller='events', return_format='stix2', eventid=event.id))
        check_response(connector.untag(event, cluster['tag_name']))
        stored = self._stored_clusters(cluster['uuid'])

        reimported = self._upload(connector, bundle)

        self.assertEqual(event.uuid, reimported['uuid'])
        self.assertEqual(
            {cluster['tag_name']},
            self._cluster_tag_names(reimported, cluster['type']))
        self.assertEqual(stored, self._stored_clusters(cluster['uuid']))

    def test_stock_user_gets_the_cluster_tag_of_the_cluster_it_creates(self):
        malware = self._malware()
        event = self._upload(self.stock_user, self._external_bundle(malware))

        cluster = self._only_cluster(malware['name'])
        tags = {tag['name']: tag for tag in event.get('Tag', [])}
        self.assertIn(cluster['tag_name'], tags)
        self.assertNotEqual(self.ATTACH_CLUSTER_COLOUR,
                            tags[cluster['tag_name']]['colour'].lower())

    def test_non_galaxy_editor_gets_only_existing_cluster_tags(self):
        known, unknown = self._malware(), self._malware()
        self._upload(self.stock_user, self._external_bundle(known))
        known_cluster = self._only_cluster(known['name'])

        event = self._upload(
            self.tag_editor, self._external_bundle(known, unknown))

        self.assertEqual(
            {known_cluster['tag_name']},
            self._cluster_tag_names(event, known_cluster['type']))
        self.assertEqual([], self._clusters(value=unknown['name']))

    def test_round_trip_of_a_default_cluster_for_a_site_admin(self):
        self._assert_round_trip_attaches_the_stored_cluster_tag(
            self.admin, self.default_cluster)

    def test_round_trip_of_a_default_cluster_for_a_stock_user(self):
        self._assert_round_trip_attaches_the_stored_cluster_tag(
            self.stock_user, self.default_cluster)

    def test_round_trip_of_a_custom_cluster_for_a_site_admin(self):
        self._assert_round_trip_attaches_the_stored_cluster_tag(
            self.admin, self._custom_cluster(self.admin))

    def test_round_trip_of_a_custom_cluster_for_a_stock_user(self):
        self._assert_round_trip_attaches_the_stored_cluster_tag(
            self.stock_user, self._custom_cluster(self.stock_user))

    def test_site_admin_gets_the_cluster_tag_of_the_cluster_it_creates(self):
        malware = self._malware()
        event = self._upload(self.admin, self._external_bundle(malware))

        cluster = self._only_cluster(malware['name'])
        self.assertEqual({cluster['tag_name']},
                         self._cluster_tag_names(event, cluster['type']))

    def test_non_tagger_gets_the_cluster_but_no_cluster_tag_created(self):
        malware = self._malware()
        event = self._upload(
            self.galaxy_editor, self._external_bundle(malware))

        cluster = self._only_cluster(malware['name'])
        self.assertEqual(set(), self._cluster_tag_names(event))
        self.assertEqual([], self.admin.search_tags(
            cluster['tag_name'], strict_tagname=True))

    def test_galaxies_as_tags_follow_the_tag_editor_rule(self):
        for connector, expected_tags in (
                (self.tag_editor, 1), (self.stock_user, 0)):
            with self.subTest(expected_tags=expected_tags):
                malware = self._malware()
                event = self._upload(
                    connector, self._external_bundle(malware),
                    galaxies_as_tags=1)

                self.assertEqual([], self._clusters(value=malware['name']))
                self.assertEqual(
                    expected_tags, len(self._cluster_tag_names(event)))


def gen_random_id() -> str:
    return str(uuid.uuid4()).split("-")[0]


if __name__ == '__main__':
    unittest.main()
