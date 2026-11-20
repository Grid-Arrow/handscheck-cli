from handscheck.agents._framework.check import CheckContext
from handscheck.sites.discovery import (
    DISCOVERY,
    SiteInventory,
    WordPressInstall,
    merge_sites,
    parse_configs,
    parse_wp_versions,
    search_roots,
)
from tests.agents.replay import ReplayRunner

APACHE = """\
/etc/apache2/sites-enabled/shop.conf:<VirtualHost *:80>
/etc/apache2/sites-enabled/shop.conf:    ServerName Shop.Example.test
/etc/apache2/sites-enabled/shop.conf:    ServerAlias www.shop.example.test
/etc/apache2/sites-enabled/shop.conf:    DocumentRoot "/var/www/shop/"
/etc/apache2/sites-enabled/shop.conf:</VirtualHost>
/etc/apache2/sites-enabled/shop.conf:<VirtualHost *:443>
/etc/apache2/sites-enabled/shop.conf:    # ServerName commented.example.test
/etc/apache2/sites-enabled/shop.conf:    ServerName shop.example.test
/etc/apache2/sites-enabled/shop.conf:    ServerAlias shop2.example.test
/etc/apache2/sites-enabled/shop.conf:    DocumentRoot /var/www/shop
/etc/apache2/sites-enabled/shop.conf:</VirtualHost>
/etc/apache2/sites-enabled/blog.conf:<VirtualHost *:80>
/etc/apache2/sites-enabled/blog.conf:  ServerName blog.example.test
/etc/apache2/sites-enabled/blog.conf:  DocumentRoot /srv/blog/public
/etc/apache2/sites-enabled/blog.conf:</VirtualHost>
"""
NGINX = """\
/etc/nginx/sites-enabled/app:server {
/etc/nginx/sites-enabled/app:    listen 80 default_server; # comment { }
/etc/nginx/sites-enabled/app:    server_name app.example.test api.example.test;
/etc/nginx/sites-enabled/app:    root /var/www/app/public;
/etc/nginx/sites-enabled/app:    location / { root /elsewhere; try_files $uri /index.php; }
/etc/nginx/sites-enabled/app:}
/etc/nginx/conf.d/default.conf:server { listen 8080; server_name _; root /usr/share/nginx/html; }
"""


def test_parse_apache_and_nginx() -> None:
    sites = parse_configs(APACHE + NGINX)
    names = [(s.name, s.server, s.docroot) for s in sites]
    assert names == [
        ("shop.example.test", "apache", "/var/www/shop"),
        ("shop.example.test", "apache", "/var/www/shop"),
        ("blog.example.test", "apache", "/srv/blog/public"),
        ("app.example.test", "nginx", "/var/www/app/public"),
        ("/usr/share/nginx/html", "nginx", "/usr/share/nginx/html"),
    ]
    app = sites[3]
    assert app.aliases == ["api.example.test"] and app.listen == ["80 default_server"]


def test_merge_attaches_wordpress_and_keeps_orphan_installs() -> None:
    installs = parse_wp_versions(
        [
            "/var/www/shop/wp-includes/version.php",
            "/var/www/shop/old/wp-includes/version.php",
            "/var/www/orphan/wp-includes/version.php",
        ],
        "/var/www/shop/wp-includes/version.php:$wp_version = '6.7.2';\n"
        '/var/www/orphan/wp-includes/version.php:$wp_version = "4.9.1";\n',
    )
    assert installs[0] == WordPressInstall(path="/var/www/orphan", version="4.9.1")
    sites = merge_sites(parse_configs(APACHE), installs)
    by_name = {s.name: s for s in sites}
    shop = by_name["shop.example.test"]
    assert shop.aliases == ["shop2.example.test", "www.shop.example.test"]
    assert shop.listen == ["*:80", "*:443"]
    assert shop.type == "wordpress" and shop.wordpress == WordPressInstall(
        path="/var/www/shop", version="6.7.2"
    )
    assert by_name["blog.example.test"].type == "unknown"
    assert by_name["/var/www/orphan"].server == "none" and by_name["/var/www/orphan"].type == "wordpress"
    # The nested install below a claimed one is listed on its own too (it's code that can be attacked).
    assert "/var/www/shop/old" in by_name


def test_search_roots_dedupe_nested() -> None:
    assert search_roots(["/var/www/shop", "/srv/blog/public", "/srv/blog", "/"]) == ["/srv/blog", "/var/www"]


async def test_lab_discovery() -> None:
    for host, expected, version in (
        ("lab-wp1", ["alpha.lab.test", "beta.lab.test"], "6.7.2"),
        ("lab-wp2", ["delta.lab.test", "gamma.lab.test"], "6.5.5"),
        ("lab-locked", [], None),
    ):
        ctx = CheckContext(runner=ReplayRunner.load(host), host=host, sudo_ok=host != "lab-locked")
        inv = await DISCOVERY.run(ctx, {})
        assert isinstance(inv, SiteInventory)
        assert [s.name for s in inv.sites] == expected
        for site in inv.sites:
            assert site.type == "wordpress" and site.wordpress and site.wordpress.version == version
            assert site.docroot == f"/var/www/{site.name}" and site.server == "apache"
