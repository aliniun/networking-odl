from neutron_lib import context as nl_context
from oslo_log import log as logging
from neutron_lib.plugins import constants as nlib_const
from neutron_lib.plugins import directory

from networking_odl.common import constants as odl_const
from networking_odl.journal import full_sync
from networking_odl.journal import journal
from neutron_fwaas.services.firewall.drivers import fwaas_base
from neutron_fwaas.db.firewall import firewall_db

LOG = logging.getLogger(__name__)

FWAAS_RESOURCES = {
    odl_const.ODL_FIREWALL: odl_const.ODL_FIREWALLS,
    odl_const.ODL_FIREWALL_POLICY: odl_const.ODL_FIREWALL_POLICYS,
    odl_const.ODL_FIREWALL_RULE: odl_const.ODL_FIREWALL_RULES
}


class OpenDaylightFwaasDriver(fwaas_base.FwaasDriverBase, firewall_db.Firewall_db_mixin):

    def __init__(self):
        LOG.debug("Initializing Opendaylight fwaas driver")
        self.pre_firewall = None
        self.journal = journal.OpenDaylightJournalThread()
        full_sync.register(nlib_const.FIREWALL, FWAAS_RESOURCES, self.get_resources)

    def create_firewall(self, agent_mode, apply_list, fw):

        fwp_id = fw['firewall_policy_id']

        context = nl_context.get_admin_context()
        get_firewall_policy = super(OpenDaylightFwaasDriver, self)._get_firewall_policy
        get_firewall_rules = super(OpenDaylightFwaasDriver, self).get_firewall_rules

        fwp = get_firewall_policy(context, fwp_id)
        if fwp:
            LOG.debug("create firewall policy first before create firewall")
            fwrs = get_firewall_rules(context, filters={'firewall_policy_id': [fwp_id]})
            if fwrs:
                LOG.debug("create firewall rules first before create firewall policy")
                for fwr in fwrs:
                    self.__create_firewall_rule__(fwr, fw)

            self.__create_firewall_policy__(fwrs, fwp, fw)

        self.__create_firewall__(fw)

    def delete_firewall(self, agent_mode, apply_list, fw):

        fwp_id = fw['firewall_policy_id']
        tenant_id = fw['tenant_id']
        fwrs = fw['firewall_rule_list']

        self.__delete_firewall__(fw['id'], tenant_id)

        if fwp_id:
            self.__delete_firewall_policy__(fwp_id, tenant_id)

        if fwrs:
            for fwr in fwrs:
                self.__delete_firewall_rule__(fwr['id'], tenant_id)

    def update_firewall(self, agent_mode, apply_list, fw):

        import pdb;
        pdb.set_trace()
        fwp_id = fw['firewall_policy_id']
        tenant_id = fw['tenant_id']

        context = nl_context.get_admin_context()

        get_firewall_policy = super(OpenDaylightFwaasDriver, self)._get_firewall_policy
        get_firewall_rules = super(OpenDaylightFwaasDriver, self).get_firewall_rules

        fwp = get_firewall_policy(context, fwp_id)
        if fwp:
            LOG.debug("update firewall policy first before create firewall")
            fwrs = get_firewall_rules(context, filters={'firewall_policy_id': [fwp_id]})
            if fwrs:
                LOG.debug("update firewall rules first before create firewall policy")
                for fwr in fwrs:
                    self.__update_firewall_rule__(fwr, fw)

            self.__update_firewall_policy__(fwrs, fwp, fw)

        self.__update_firewall__(fw)

    def apply_default_policy(self, agent_mode, apply_list, firewall):
        pass

    def __create_firewall__(self, fw):
        LOG.debug('Creating firewall %(fw_id)s for tenant %(tid)s',
                  {'fw_id': fw['id'], 'tid': fw['tenant_id']})
        context = nl_context.get_admin_context()
        fw_format = self.format_firewall(fw)
        self._journal_record(context, odl_const.ODL_FIREWALL, fw['id'],
                             odl_const.ODL_CREATE, fw_format)

    def __update_firewall__(self, fw):
        LOG.debug('Updating firewall %(fw_id)s for tenant %(tid)s',
                  {'fw_id': fw['id'], 'tid': fw['tenant_id']})
        context = nl_context.get_admin_context()
        self._journal_record(context, odl_const.ODL_FIREWALL, fw['id'],
                             odl_const.ODL_UPDATE, fw)

    def __delete_firewall__(self, fw_id, tenant_id):
        LOG.debug('Deleting firewall %(fw_id)s for tenant %(tid)s',
                  {'fw_id': fw_id, 'tid': tenant_id})
        context = nl_context.get_admin_context()
        self._journal_record(context, odl_const.ODL_FIREWALL, fw_id,
                             odl_const.ODL_DELETE)

    def __create_firewall_policy__(self, fwrs, fwp, fw):
        LOG.debug('Creating firewallPolicy %(fwp_id)s for tenant %(tid)s',
                  {'fwp_id': fwp['id'], 'tid': fw['tenant_id']})
        context = nl_context.get_admin_context()
        fwp_format = self.format_firewall_policy(fwrs, fwp, fw)
        self._journal_record(context, odl_const.ODL_FIREWALL_POLICY, fwp['id'],
                             odl_const.ODL_CREATE, fwp_format)

    def __update_firewall_policy__(self, fwrs, fwp, fw):
        LOG.debug('Updating firewallPolicy %(fwp_id)s for tenant %(tid)s',
                  {'fwp_id': fwp['id'], 'tid': fwp['tenant_id']})
        fwp_format = self.format_firewall_policy(fwrs, fwp, fw)
        context = nl_context.get_admin_context()
        self._journal_record(context, odl_const.ODL_FIREWALL_POLICY, fwp['id'],
                             odl_const.ODL_UPDATE, fwp)

    def __delete_firewall_policy__(self, fwp_id, tenant_id):
        LOG.debug('Deleting firewallPolicy %(fwp_id)s for tenant %(tid)s',
                  {'fwp_id': fwp_id, 'tid': tenant_id})
        context = nl_context.get_admin_context()
        self._journal_record(context, odl_const.ODL_FIREWALL_POLICY, fwp_id,
                             odl_const.ODL_DELETE)

    def __create_firewall_rule__(self, fwr, fw):
        LOG.debug('Creating firewall %(fwr_id)s for tenant %(tid)s',
                  {'fwr_id': fwr['id'], 'tid': fwr['tenant_id']})
        fwr_format = self.format_firewall_rule(fwr, fw)

        context = nl_context.get_admin_context()
        self._journal_record(context, odl_const.ODL_FIREWALL_RULE, fwr_format['id'],
                             odl_const.ODL_CREATE, fwr_format)

    def __update_firewall_rule__(self, fwr, fw):
        LOG.debug('Creating firewall %(fwr_id)s for tenant %(tid)s',
                  {'fwr_id': fwr['id'], 'tid': fw['tenant_id']})
        fwr_format = self.format_firewall_rule(fwr, fw)
        context = nl_context.get_admin_context()
        self._journal_record(context, odl_const.ODL_FIREWALL_RULE, fwr_format['id'],
                             odl_const.ODL_DELETE, fwr_format)

    def __delete_firewall_rule__(self, fwr_id, tenant_id):
        LOG.debug('Deleting firewall %(fwr_id)s for tenant %(tid)s',
                  {'fwr_id': fwr_id, 'tid': tenant_id})

        context = nl_context.get_admin_context()
        self._journal_record(context, odl_const.ODL_FIREWALL_RULE, fwr_id,
                             odl_const.ODL_DELETE)

    def format_firewall(self, fw):
        fw_format = {}
        fw_format['id'] = fw['id']
        fw_format['tenant_id'] = fw['tenant_id']
        fw_format['name'] = fw['name']
        fw_format['shared'] = fw['shared']
        fw_format['admin_state_up'] = fw['admin_state_up']
        fw_format['status'] = fw['status']
        fw_format['firewall_policy_id'] = fw['firewall_policy_id']
        fw_format['description'] = fw['description']
        return fw_format

    def format_firewall_policy(self, fwrs, fwp, fw):
        fwp_format = {}
        fwp_format['id'] = fwp['id']
        fwp_format['tenant_id'] = fw['tenant_id']
        fwp_format['name'] = fwp['name']
        fwp_format['shared'] = fwp['shared']
        fwp_format['audited'] = fwp['audited']
        fwp_format['firewall_rule_ids'] = []
        for fwr in fwrs:
            if fwr['id']:
                fwp_format['firewall_rule_ids'].append(fwr['id'])
        return fwp_format

    def format_firewall_rule(self, fwr, fw):
        fwr_format = {}
        fwr_format['tenant_id'] = fwr['tenant_id']
        fwr_format['name'] = fwr['name']
        fwr_format['shared'] = fwr['shared']
        fwr_format['firewall_policy_id'] = fwr['firewall_policy_id']
        fwr_format['protocol'] = fwr['protocol']
        fwr_format['ip_version'] = fwr['ip_version']
        fwr_format['source_ip_address'] = fwr['source_ip_address']
        fwr_format['destination_ip_address'] = fwr['destination_ip_address']
        fwr_format['position'] = fwr['position']
        fwr_format['action'] = fwr['action']
        fwr_format['enabled'] = fwr['enabled']
        fwr_format['id'] = fwr['id']

        fwr_format['admin_state_up'] = fw['admin_state_up']

        fwr_format['source_port_range_min'] = fwr['source_port']
        fwr_format['source_port_range_max'] = fwr['source_port']

        if fwr['source_port']:
            if str(fwr['source_port']).find(':') != -1:
                src_port_min_max = self.get_port_range(fwr['source_port'])
                fwr_format['source_port_range_min'] = int(src_port_min_max[0])
                fwr_format['source_port_range_max'] = int(src_port_min_max[1])
            else:
                fwr_format['source_port_range_min'] = int(fwr['source_port'])
                fwr_format['source_port_range_max'] = int(fwr['source_port'])

        fwr_format['destination_port_range_min'] = fwr['destination_port']
        fwr_format['destination_port_range_max'] = fwr['destination_port']
        if fwr['destination_port']:
            if fwr['destination_port'].find(':') != -1:
                dst_port_min_max = self.get_port_range(fwr['destination_port'])
                fwr_format['destination_port_range_min'] = int(dst_port_min_max[0])
                fwr_format['destination_port_range_max'] = int(dst_port_min_max[1])
            else:
                fwr_format['destination_port_range_min'] = int(fwr['destination_port'])
                fwr_format['destination_port_range_max'] = int(fwr['destination_port'])
        return fwr_format

    def get_port_range(self, port_min_max):
        try:
            src_port_min_max = str(port_min_max).split(':')
            if src_port_min_max[0] and src_port_min_max[1]:
                return src_port_min_max
        except Exception:
            raise Exception

    def _journal_record(self, context, obj_type, obj_id, operation, obj):
        journal.record(context, obj_type, obj_id, operation, obj)
        self.journal.set_sync_event()

    @staticmethod
    def get_resources(context, resource_type):
        plugin = directory.get_plugin(nlib_const.FIREWALL)
        # if resource_type == odl_const.ODL_MEMBER:
        #     return full_sync.get_resources_require_id(plugin, context,
        #                                               plugin.get_pools,
        #                                               'get_pool_members')
        obj_getter = getattr(plugin, 'get_%s' % FWAAS_RESOURCES[resource_type])


class OpenDaylightManager():

    def __init__(self, obj_type):
        LOG.debug("Initializing OpenDaylight FWaaS driver")
        self.journal = journal.OpenDaylightJournalThread()
        self.obj_type = obj_type
        full_sync.register(nlib_const.FIREWALL, FWAAS_RESOURCES,
                           self.get_resources)

    def _journal_record(self, context, obj_type, obj_id, operation, obj):
        journal.record(context, obj_type, obj_id, operation, obj.to_api_dict())
        self.journal.set_sync_event()

    @staticmethod
    def get_resources(context, resource_type):
        plugin = directory.get_plugin(nlib_const.FIREWALL)
        # if resource_type == odl_const.ODL_MEMBER:
        #     return full_sync.get_resources_require_id(plugin, context,
        #                                               plugin.get_pools,
        #                                               'get_pool_members')

        obj_getter = getattr(plugin, 'get_%s' % FWAAS_RESOURCES[resource_type])
        return obj_getter(context)
