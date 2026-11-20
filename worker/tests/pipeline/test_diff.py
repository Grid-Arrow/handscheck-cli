from datetime import UTC, datetime

from handscheck.agents.system.check import SystemFacts
from handscheck.pipeline.diff import Change, diff_views
from handscheck.pipeline.events import change_events

AT = datetime(2026, 11, 14, tzinfo=UTC)


def test_added_removed_changed() -> None:
    before = {"users": {"bob": {"uid": 1000}, "eve": {"uid": 1001}}, "only_before": {"x": 1}}
    after = {"users": {"bob": {"uid": 0}, "mallory": {"uid": 1002}}, "only_after": {"y": 1}}
    changes = diff_views("users", before, after)
    assert [(c.collection, c.key, c.op) for c in changes] == [
        ("users", "mallory", "added"),
        ("users", "eve", "removed"),
        ("users", "bob", "changed"),
    ]
    assert changes[2].before == {"uid": 1000} and changes[2].after == {"uid": 0}
    # Collections missing on one side are not compared ("couldn't look" is not "everything vanished").
    assert all(c.collection == "users" for c in changes)


def test_append_only_collections_ignore_removals() -> None:
    before = {"auth_events": {"a": "line a"}}
    after = {"auth_events": {"b": "line b"}}
    changes = diff_views("users", before, after, append_only={"auth_events"})
    assert [(c.key, c.op) for c in changes] == [("b", "added")]


def test_json_round_trip_is_not_a_change() -> None:
    before = {"c": {"k": {"lines": ("a", "b")}}}
    after = {"c": {"k": {"lines": ["a", "b"]}}}
    assert diff_views("x", before, after) == []


def test_fixture_like_changes_and_events() -> None:
    clean = SystemFacts(
        kernel="6.8.0-40", boot_id="b1", uid0_accounts=["root"], packages={"bash": "5.2", "sudo": "1.9.15"}
    )
    hacked = clean.model_copy(
        update={
            "kernel": "6.8.0-45",
            "boot_id": "b2",
            "uid0_accounts": ["root", "sysbackup"],
            "packages": {"bash": "5.2", "sudo": "1.9.16", "netcat": "1.2"},
        }
    )
    changes = diff_views("system", clean.diff_view(), hacked.diff_view())
    summary = {(c.collection, c.key, c.op) for c in changes}
    assert ("uid0_accounts", "sysbackup", "added") in summary
    assert ("boot", "boot_id", "changed") in summary
    events = change_events(changes, AT)
    assert [(e.kind, e.summary) for e in events] == [
        ("reboot", "host rebooted into kernel 6.8.0-45"),
        ("package", "packages 1 upgraded, 1 installed"),
    ]
    assert events[1].detail["upgraded"] == {"sudo": {"from": "1.9.15", "to": "1.9.16"}}


def test_site_events() -> None:
    changes = [
        Change(
            agent="sites", collection="sites", key="new.test", op="added", after={"docroot": "/var/www/new"}
        ),
        Change(agent="sites", collection="sites", key="old.test", op="removed", before={"docroot": "/x"}),
        Change(agent="sites", collection="sites", key="same.test", op="changed", before={}, after={}),
    ]
    events = change_events(changes, AT)
    assert [(e.kind, e.site, e.summary) for e in events] == [
        ("site", "new.test", "new site discovered: new.test"),
        ("site", "old.test", "site no longer found: old.test"),
    ]
    assert events[0].detail == {"op": "added", "docroot": "/var/www/new"}


def test_describe() -> None:
    assert Change(agent="a", collection="c", key="k", op="added", after=True).describe() == "c: added k"
    changed = Change(agent="a", collection="c", key="k", op="changed", before="1", after="2")
    assert changed.describe() == "c: k: 1 → 2"


def test_wordpress_package_events() -> None:
    changes = [
        Change(
            agent="wordpress",
            site="s",
            collection="core",
            key="version",
            op="changed",
            before="6.5",
            after="6.7",
        ),
        Change(
            agent="wordpress",
            site="s",
            collection="plugins",
            key="akismet",
            op="changed",
            before="5.3",
            after="5.4",
        ),
        Change(agent="wordpress", site="s", collection="plugins", key="new", op="added", after="1.0"),
        Change(agent="wordpress", site="s", collection="admins", key="root", op="added", after={}),
    ]
    [event] = change_events(changes, AT)
    assert (event.kind, event.agent, event.site) == ("package", "wordpress", "s")
    assert event.summary == "WordPress: core 6.5 → 6.7, 1 plugins installed, 1 plugins updated"
    assert event.detail["plugins_updated"] == {"akismet": {"from": "5.3", "to": "5.4"}}
