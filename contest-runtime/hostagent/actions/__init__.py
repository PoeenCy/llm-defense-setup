"""Whitelist of everything the dashboard can ask the host to do. A request
naming anything not in ACTIONS is refused."""
from . import config, ctfproxy, firewall, oswatchdog, services, suricata

ACTIONS = {
    "suricata_apply": suricata.apply,
    "suricata_rollback": suricata.rollback,
    "suricata_test_traffic": suricata.test_traffic,
    "suricata_delete_rule": suricata.delete_rule,
    "ctfproxy_services": ctfproxy.list_services,
    "ctfproxy_get": ctfproxy.get,
    "ctfproxy_apply": ctfproxy.apply,
    "ctfproxy_rollback": ctfproxy.rollback,
    "ctfproxy_delete_method": ctfproxy.delete_method,
    "services_list": services.list_services,
    "service_control": services.control,
    "config_validate": config.validate,
    "config_apply": config.apply,
    "config_rollback": config.rollback,
    "config_redeploy_log": config.redeploy_log,
    "firewall_list": firewall.list_blocks,
    "firewall_block": firewall.block_ip,
    "firewall_unblock": firewall.unblock_ip,
    "firewall_content_list": firewall.list_content_blocks,
    "firewall_content_block": firewall.block_content,
    "firewall_content_unblock": firewall.unblock_content,
    "oswatchdog_allow": oswatchdog.allow,
    "oswatchdog_unallow": oswatchdog.unallow,
    "oswatchdog_list_allowed": oswatchdog.list_allowed,
}
