from pyakuvox.network import (
    ConfigKeyMap,
    CustomPostProfile,
    build_config_set_payload,
    plan_static_network,
    render_body,
    render_url,
)


def test_plan_static_network_preserves_host_offset() -> None:
    config = plan_static_network(
        "192.168.110.251",
        "192.168.110.0/24",
        "10.0.0.0/24",
    )

    assert config.new_ip == "10.0.0.251"
    assert config.netmask == "255.255.255.0"
    assert config.gateway == "10.0.0.1"


def test_render_custom_post_profile() -> None:
    profile = CustomPostProfile(
        name="example",
        url_template="http://{old_ip}/network",
        body_template="ip={new_ip}&mask={netmask}&gw={gateway}&dns={dns1}",
    )
    config = plan_static_network(
        "192.168.110.251",
        "192.168.110.0/24",
        "10.0.0.0/24",
    )

    assert render_url(profile, config) == "http://192.168.110.251/network"
    assert render_body(profile, config) == (
        "ip=10.0.0.251&mask=255.255.255.0&gw=10.0.0.1&dns=8.8.8.8"
    )


def test_build_config_set_payload_requires_explicit_key_map() -> None:
    config = plan_static_network(
        "192.168.110.251",
        "192.168.110.0/24",
        "10.0.0.0/24",
    )
    payload = build_config_set_payload(
        config,
        ConfigKeyMap(
            dhcp="Network.DHCP",
            ip="Network.IPAddress",
            netmask="Network.SubnetMask",
            gateway="Network.Gateway",
            dns1="Network.DNS1",
            dns2="Network.DNS2",
        ),
    )

    assert payload == {
        "Network.DHCP": "0",
        "Network.IPAddress": "10.0.0.251",
        "Network.SubnetMask": "255.255.255.0",
        "Network.Gateway": "10.0.0.1",
        "Network.DNS1": "8.8.8.8",
        "Network.DNS2": "1.1.1.1",
    }
