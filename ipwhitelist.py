#!/usr/bin/env python3
# fmt: off
import argparse
import ipaddress
import os
import re
import socket
import warnings
from collections.abc import Callable
from datetime import datetime
from typing import Any

import boto3
import botocore
import requests
import yaml
from kubernetes import client, config
from kubernetes.client import V1Service

# Turn off warnings about unverified HTTPS requests and Python version support in boto3
warnings.filterwarnings( 'ignore', message = 'Unverified HTTPS request' )
warnings.filterwarnings( 'ignore', message = 'Boto3 will no longer support Python 3.5' )
warnings.filterwarnings( 'ignore', message = 'Boto3 will no longer support Python 3.7' )


# Some nice constants
OVERRIDES_FP = '/srv/pillar/custom/overrides.sls'
TRAEFIK_INGRESS_INT_FP = '/domino/k8s/traefik-ingress-internal-service.yaml'
TRAEFIK_INGRESS_EXT_FP = '/domino/k8s/traefik-ingress-external-service.yaml'


# Helper class for some nice colours in ANSI terminals
class C:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Helper class to interact with Domino
class Domino:
    def __init__( self, url ):
        # Sanity check URL and pull out scheme and hostname/port
        pu = requests.utils.urlparse( url )
        if pu.scheme is None or pu.scheme not in [ 'http', 'https' ]:
            raise ValueError( "Argument url does not have a valid scheme. Only 'http' and 'https' supported." )
        if pu.netloc is None:
            raise ValueError( 'Argument url does not contain a hostname.' )
        self._url = url

        # Connect to scheme://hostname:port/version to grab the version in JSON format
        version_url = f"{pu.scheme}://{pu.netloc}/version"
        r = requests.get( version_url, verify = False, timeout = 30 )
        if not r.ok:
            raise RuntimeError(f"HTTP request to get Domino version failed with HTTP code {r.status_code} {r.reason}")
        self._version = r.json()[ 'version' ]

        build = None
        ( major, minor, patch ) = self._version.split( '.', 2 )
        if '-' in patch:
            ( patch, build ) = patch.split( '-', 1 )
        self._major = int( major )
        self._minor = int( minor )
        self._patch = int( patch )
        self._build = str( build )

        # Only major versions 3 and 4 supported at present
        if self._major < 3 or self._major > 5:
            raise RuntimeError( 'Unsupported Domino version ' + self._version )

    @property
    def version( self ):
        return self._version

    @property
    def major( self ):
        return self._major

    @property
    def minor( self ):
        return self._minor

    @property
    def patch( self ):
        return self._patch

    @property
    def build( self ):
        return self._build


# Helper class to deal with protocol names and numbers
class Protocols:
    def __init__( self ):
        self.__protocols = { num: name[8:] for name, num in vars( socket ).items() if name.startswith( "IPPROTO" ) }

    @staticmethod
    def get_protocol_number( protocol_name ):
        return socket.getprotobyname( protocol_name )

    def get_protocol_name( self, protocol_number ):
        if protocol_number == '-1':
            protocol_name = 'ALL'
        else:
            try:
                protocol_name = self.__protocols[ int( protocol_number ) ]
            except ValueError:
                protocol_name = str( protocol_number ).upper()
            except KeyError:
                protocol_name = f'proto({protocol_number})'
        return protocol_name

    @staticmethod
    def get_service_port( service_name, protocol ):
        return socket.getservbyname( service_name, protocol )

    @staticmethod
    def get_service_name( port_number, protocol ):
        service_name = '-'
        if '-' not in port_number:
            try:
                service_name = socket.getservbyport( int( port_number ), protocol.lower() ).upper()
            except ValueError:
                pass
            except OSError:
                pass
        return service_name


# Argparse type function to validate a VPC ID
# VPC ID format is 'vpc-[0-0a-f]{17}'
def __validate_vpc_id( v ):
    if not re.search( 'vpc-[0-9a-f]{17}', v ):
        raise argparse.ArgumentTypeError( '%s is not a valid VPC ID' % v )
    return v


# Argparse type function to validate argument value is a CIDR or security group
# CIDR format is 'A.B.C.D/E' where A,B,C & D are octets and E is a 5-bit number
# SG format is 'sg-[0-9a-f]{17}'
def __validate_cidr_or_sg( v ):
    try:
        ipaddress.ip_network( v )
        x = { 'cidr': str( v ) }
    except ValueError as e:
        if re.search( '^sg-[0-9a-f]{17}$', v ):
            x = { 'security-group': str( v ) }
        else:
            raise argparse.ArgumentTypeError( '%s is not a CIDR or Security Group ID' % v ) from e
        raise RuntimeError( 'NOT IMPLEMENTED: Adding Security Groups as a source is currently not implemented.' ) from e
    return x


# Argparse type function to validate a port number
# Valid port numbers are 16-bit unsigned integers or the text 'ALL'
def __validate_port_num( v ):
    if v == 'ALL':
        x = -1
    else:
        x = int( v )
        if x < 0 or x > 65535:
            raise argparse.ArgumentTypeError( '%s is not a valid port number' % v )
    return x


# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser( description = 'A script to facilitate IP whitelisting for '
                                                    'Domino Data Lab deployments.' )

    # URL of FE including scheme and port number, stage name and either VPC name or VPC ID
    parser.add_argument( '-u', '--url', type = str, required = True, help = 'The frontend URL of the deployment. '
                                                                            'Used to get Domino version. If '
                                                                            'not supplied, the script will attempt to '
                                                                            'auto-detect the deployment.' )
    parser.add_argument( '-s', '--stage-name', type = str, required = True, help = 'Deployment stage name.' )
    parser.add_argument( '--platform-namespace', type = str, required = False, help = 'Platform namespace.' )
    group_vpc = parser.add_mutually_exclusive_group()
    group_vpc.add_argument( '--vpc', type = str, help = 'The VPC name for your Domino deployment.' )
    group_vpc.add_argument( '--vpcid', type = __validate_vpc_id, dest='vpc_id',
                            help = 'The VPC ID for your Domino deployment.' )

    # Parent parser containing arguments common to both adding and removing whitelist entries
    parser_common = argparse.ArgumentParser( description = 'Arguments common to both adding and removing whitelist '
                                                           'entries.', add_help = False )
    parser_common.add_argument( '-e', '--execute', default = False, action = 'store_true',
                                help = 'Actually modify security groups and configuration files (default is dry '
                                       'run only.)' )
    parser_common.add_argument( '-c', '--source', type = __validate_cidr_or_sg, required = True,
                                help = 'The source CIDR or security group ID to add/remove.' )
    '''
    parser_common.add_argument( '-p', '--port', type = __validate_port_num, default = 'ALL',
                                help = 'The port or port range (i.e. "443" or "49000-49999") to add/remove. '
                                'Ignored if protocol is "ALL". Defaults to "ALL" (i.e. 0-65535.)' )
    parser_common.add_argument( '-t', '--protocol', type = str, required = True, choices = [ 'TCP', 'UDP', 'ALL' ],
                                help='The IP protocol to add/remove.' )
    '''

    # Commands to list, describe and modify whitelists
    subparser = parser.add_subparsers( title = 'subcommands', dest = 'command' )
    parser_list_sgs = subparser.add_parser( 'list-security-groups', aliases = [ 'list' ],  # noqa: F841
                                            help = 'List current security groups.' )
    parser_show_wl = subparser.add_parser( 'show-whitelist', aliases = [ 'show' ],  # noqa: F841
                                           help = 'Shows current whitelist.' )
    parser_add = subparser.add_parser( 'add-whitelist', aliases = [ 'add' ], parents = [ parser_common ],  # noqa: F841
                                       help = 'Adds a whitelist entry.' )
    parser_remove = subparser.add_parser( 'remove-whitelist', aliases = [ 'remove' ],  # noqa: F841
                                          parents = [ parser_common ], help = 'Removes a whitelist entry.' )

    args = parser.parse_args()
    if not args.command:
        print( 'No command specified, nothing to do!' )
        parser.print_usage()
        exit( 1 )

    return args


# Helper function to find index of FIRST key of given value in list of dictionaries.
# Returns index or None if not found.
def __find_key_in_list( lst, ky, val ):
    for enm in lst:
        if enm[ ky ] == val:
            return enm
    return None


# Given a VPC name, find an EC2 VPC with that name and return its VPC ID
def get_vpc_id( vpc_name ):
    ec2 = __get_boto3_ec2_client()
    r = ec2.describe_vpcs( Filters = [ { 'Name': 'tag:Name', 'Values': [ vpc_name ] } ] )
    try:
        vpc_id = r[ 'Vpcs' ][ 0 ][ 'VpcId' ]
    except IndexError:
        vpc_id = None
    return vpc_id


def get_security_groups( vpc_id ):
    ec2 = __get_boto3_ec2_client()
    r = ec2.describe_security_groups( Filters = [ { 'Name': 'vpc-id', 'Values': [ vpc_id ] } ] )
    return r[ 'SecurityGroups' ]


def __print_row( sg_id, sg_name, port_type, protocol, port_range, source, description, header = False ):
    colour = '' if not header else C.BOLD + C.HEADER
    print( colour
           + sg_id.ljust( 21 ) + '\t'
           + sg_name.ljust( 30 )[ :30 ] + '\t'
           + port_type.ljust( 10 ) + '\t'
           + protocol.ljust( 12 ) + '\t'
           + port_range.ljust( 11 ) + '\t'
           + source.ljust( 18 ) + '\t'
           + description
           + C.ENDC )


def list_security_groups( vpc_id ):
    sgs = get_security_groups( vpc_id )
    if not sgs:
        print( C.BOLD + C.HEADER + 'No security groups found.' + C.ENDC )
        return

    max_name_len = len( max( sgs, key = lambda x: len( x[ 'GroupName' ] ) )[ 'GroupName' ] )
    for i, sg in enumerate( sgs ):
        print( C.BOLD + C.HEADER + 'ID: ' + C.ENDC + sg[ 'GroupId' ]
               + C.BOLD + C.HEADER + '\tName: ' + C.ENDC + sg[ 'GroupName' ].ljust( max_name_len )
               + C.BOLD + C.HEADER + '\tDescription: ' + C.ENDC + sg[ 'Description' ] )
    return


def show_whitelist( vpc_id ):
    sgs = get_security_groups( vpc_id )
    if not sgs:
        print( C.BOLD + C.HEADER + 'No security groups found.' + C.ENDC )
        return

    protos = Protocols()
    __print_row( 'Security Group ID', 'Security Group Name', 'Type', 'Protocol', 'Port range', 'Source',
                 'Description', header = True )
    for i, sg in enumerate( sgs ):
        for j, perm in enumerate( sg[ 'IpPermissions' ] ):
            # Try to determine the protocol name
            protocol = protos.get_protocol_name( perm[ 'IpProtocol' ] )

            # We won't deal with ICMP for now. It will need special handling of
            # FromPort / ToPort if we do in the future
            if protocol in [ 'ICMP', 'ICMPV6' ]:
                continue

            # Construct port range which will either be a single port, a range of ports (e.g. 49000-49999)
            # or ALL if no ports are given.
            if 'FromPort' not in perm:
                port_range = 'ALL'
            else:
                port_range = str( perm[ 'FromPort' ] )
                if perm[ 'ToPort' ] != perm[ 'FromPort' ] and perm[ 'ToPort' ] != -1:
                    port_range = port_range + '-' + str( perm[ 'ToPort' ] )

            # If a single port then try to determine the service name
            service_name = protos.get_service_name( port_range, protocol )

            # Enumerate the IP ranges in the security group and display the information
            for k, dest in enumerate( perm[ 'IpRanges' ] ):
                desc = dest[ 'Description' ] if 'Description' in dest else ''
                __print_row( sg[ 'GroupId' ], sg[ 'GroupName' ], service_name, protocol, port_range,
                             dest[ 'CidrIp' ], desc  )

            # Enumerate the User ID Group Pairs in the security group and display the information
            for k, dest in enumerate( perm[ 'UserIdGroupPairs' ] ):
                desc = dest[ 'Description' ] if 'Description' in dest else ''
                __print_row( sg[ 'GroupId' ], sg[ 'GroupName' ], service_name, protocol, port_range,
                             dest[ 'GroupId' ], desc  )
    return


def __remove_sg_rule( group_id, source, port, protocol, execute = False ):
    dry_run = not execute
    ec2 = __get_boto3_ec2_client()
    if 'cidr' not in source:
        raise RuntimeError( 'NOT IMPLEMENTED: Only CIDRs supported at present.' )

    cidr = source[ 'cidr' ]
    from_port = to_port = port
    if protocol != 'icmp' and '-' in str( port ):
        (from_port, to_port) = str( port ).split( '-', 1 )
    if not to_port:
        to_port = from_port
    try:
        print( f'Updating SG {group_id} to remove CIDR {cidr} port {port} {protocol}' )
        ec2.revoke_security_group_ingress(
            CidrIp = cidr,
            FromPort = int( from_port ),
            GroupId = group_id,
            IpProtocol = protocol,
            ToPort = int( to_port ),
            DryRun = dry_run
        )
    except botocore.exceptions.ClientError as e:
        error = e.response[ 'Error' ]
        if error[ 'Code' ] in ( 'DryRunOperation', 'InvalidPermission.NotFound' ):
            print( error[ 'Message' ] )
        else:
            raise e


def __add_sg_rule( group_id, source, port, protocol, execute = False ):
    dry_run = not execute
    ec2 = __get_boto3_ec2_client()
    if 'cidr' not in source:
        raise RuntimeError( 'NOT IMPLEMENTED: Only CIDRs supported at present.' )

    cidr = source[ 'cidr' ]
    from_port = to_port = port
    if protocol != 'icmp' and '-' in str( port ):
        (from_port, to_port) = str( port ).split( '-', 1 )
    if not to_port:
        to_port = from_port
    try:
        print( f'Updating SG {group_id} to add CIDR {cidr} port {port} {protocol}' )
        ec2.authorize_security_group_ingress(
            CidrIp = cidr,
            FromPort = int( from_port ),
            GroupId = group_id,
            IpProtocol = protocol,
            ToPort = int( to_port ),
            DryRun = dry_run
        )
    except botocore.exceptions.ClientError as e:
        error = e.response[ 'Error' ]
        if error[ 'Code' ] in ( 'DryRunOperation', 'InvalidPermission.Duplicate' ):
            print( error[ 'Message' ] )
        else:
            raise e


def __yaml_load( filename: str ) -> Any:
    with open( filename ) as f:
        content = yaml.load( f, Loader=yaml.FullLoader )
        return content


def __yaml_dump( dt, execute, filename, ingress ):
    if execute:
        fname = filename
        os.rename( fname, fname + '.bak_' + dt )
    else:
        fname = filename + '.dryrun_' + dt
    with open( fname, 'w' ) as f:
        yaml.dump( ingress, f )


def __append_action( cidr: str, cidrs: list ) -> bool:
    if cidr not in cidrs:
        cidrs.append( cidr )
        return True
    return False


def __add_cidr_to_traefik_ingress( filename, cidr, k8s_client, dt, execute ):
    ingress = __yaml_load( filename )
    if __append_action( cidr, ingress[ 'spec' ][ 'loadBalancerSourceRanges' ] ):
        __yaml_dump( dt, execute, filename, ingress )
        if execute:
            k8s_client.patch_namespaced_service( ingress[ 'metadata' ][ 'name' ], 'default', ingress )


def __add_cidr_to_overrides_v3( filename, cidr, dt, execute ):
    overrides = __yaml_load( filename )
    overrides_provisioning_aws = overrides[ 'provisioning' ][ 'aws' ]
    if ( __append_action( cidr, overrides_provisioning_aws[ 'security_group_admin_cidrs' ] )
         or __append_action( cidr, overrides_provisioning_aws[ 'security_group_access_cidrs' ] ) ):
        __yaml_dump( dt, execute, filename, overrides )


def add_whitelist_v3( vpc_id, stage_name, source, execute = False ):
    if 'cidr' in source:
        cidr = source[ 'cidr' ]
        dt = datetime.now().strftime( '%Y%m%d_%H%M%S' )
        v1 = __get_kube_core_client()
        __add_cidr_to_overrides_v3( OVERRIDES_FP, cidr, dt, execute )
        __add_cidr_to_traefik_ingress( TRAEFIK_INGRESS_EXT_FP, cidr, v1, dt, execute )
        __add_cidr_to_traefik_ingress( TRAEFIK_INGRESS_INT_FP, cidr, v1, dt, execute )

    sgs = get_security_groups( vpc_id )

    sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-general-admin' )
    group_id = sg[ 'GroupId' ]
    __add_sg_rule( group_id, source, 22, 'tcp', execute )
    __add_sg_rule( group_id, source, -1, 'icmp', execute )

    try:
        sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-domino_fe_ext_elb' )
        group_id = sg[ 'GroupId' ]
    except KeyError:
        sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-general-access' )
        group_id = sg[ 'GroupId' ]
    __add_sg_rule( group_id, source, 80, 'tcp', execute )
    __add_sg_rule( group_id, source, 443, 'tcp', execute )

    sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-executor' )
    group_id = sg[ 'GroupId' ]
    __add_sg_rule( group_id, source, 22, 'tcp', execute )
    __add_sg_rule( group_id, source, 9000, 'tcp', execute )
    __add_sg_rule( group_id, source, '49000-49999', 'tcp', execute )
    __add_sg_rule( group_id, source, -1, 'icmp', execute )

    sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-domino_fe_int' )
    if sg:
        group_id = sg[ 'GroupId' ]
        __add_sg_rule( group_id, source, 80, 'tcp', execute )
        __add_sg_rule( group_id, source, 443, 'tcp', execute )
        __add_sg_rule( group_id, source, 9000, 'tcp', execute )


def remove_whitelist_v3( vpc_id, stage_name, source, execute = False ):
    if 'cidr' in source:
        cidr = source[ 'cidr' ]
        dt = datetime.now().strftime( '%Y%m%d_%H%M%S' )
        v1 = __get_kube_core_client()
        __remove_cidr_from_overrides_v3( OVERRIDES_FP, cidr, dt, execute )
        __remove_cidr_from_traefik_ingress_v3( TRAEFIK_INGRESS_EXT_FP, cidr, v1, dt, execute )
        __remove_cidr_from_traefik_ingress_v3( TRAEFIK_INGRESS_INT_FP, cidr, v1, dt, execute )

    sgs = get_security_groups( vpc_id )

    sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-general-admin' )
    group_id = sg[ 'GroupId' ]
    __remove_sg_rule( group_id, source, 22, 'tcp', execute )
    __remove_sg_rule( group_id, source, -1, 'icmp', execute )

    try:
        sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-domino_fe_ext_elb' )
        group_id = sg[ 'GroupId' ]
    except KeyError:
        sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-general-access' )
        group_id = sg[ 'GroupId' ]
    __remove_sg_rule( group_id, source, 80, 'tcp', execute )
    __remove_sg_rule( group_id, source, 443, 'tcp', execute )

    sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-executor' )
    group_id = sg[ 'GroupId' ]
    __remove_sg_rule( group_id, source, 22, 'tcp', execute )
    __remove_sg_rule( group_id, source, 9000, 'tcp', execute )
    __remove_sg_rule( group_id, source, '49000-49999', 'tcp', execute )
    __remove_sg_rule( group_id, source, -1, 'icmp', execute )

    sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-domino_fe_int' )
    if sg:
        group_id = sg[ 'GroupId' ]
        __remove_sg_rule( group_id, source, 80, 'tcp', execute )
        __remove_sg_rule( group_id, source, 443, 'tcp', execute )
        __remove_sg_rule( group_id, source, 9000, 'tcp', execute )


def __remove_action(cidr: str, cidrs: list) -> bool:
    if cidr in cidrs:
        cidrs.remove(cidr)
        return True
    return False


def __remove_cidr_from_traefik_ingress_v3( filename, cidr, k8s_client, dt, execute ):
    ingress = __yaml_load( filename )
    if __remove_action( cidr, ingress[ 'spec' ][ 'loadBalancerSourceRanges' ] ):
        __yaml_dump( dt, execute, filename, ingress )
        if execute:
            k8s_client.patch_namespaced_service( ingress[ 'metadata' ][ 'name' ], 'default', ingress )


def __remove_cidr_from_overrides_v3( filename, cidr, dt, execute ):
    overrides = __yaml_load( filename )
    overrides_provisioning_aws = overrides[ 'provisioning' ][ 'aws' ]
    if ( __remove_action( cidr, overrides_provisioning_aws[ 'security_group_admin_cidrs' ] )
         or __remove_action( cidr, overrides_provisioning_aws[ 'security_group_access_cidrs' ] ) ):
        __yaml_dump( dt, execute, filename, overrides )


def add_whitelist_v4( vpc_id, stage_name, platform_namespace, source, execute ):
    if 'cidr' in source:
        cidr = source[ 'cidr' ]

        v1 = __get_kube_core_client()

        nic_svc = v1.read_namespaced_service( 'nginx-ingress-controller', platform_namespace )
        if __append_action( cidr, nic_svc.spec.load_balancer_source_ranges ) and execute:
            v1.patch_namespaced_service( nic_svc.metadata.name, platform_namespace, nic_svc )

    sgs = get_security_groups( vpc_id )

    sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-general-admin' )
    group_id = sg[ 'GroupId' ]
    __add_sg_rule( group_id, source, 22, 'tcp', execute )
    __add_sg_rule( group_id, source, -1, 'icmp', execute )

    try:
        sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-domino_fe_ext_elb' )
        group_id = sg[ 'GroupId' ]
    except ( KeyError, TypeError ):
        sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-general-access' )
        group_id = sg[ 'GroupId' ]
    __add_sg_rule( group_id, source, 80, 'tcp', execute )
    __add_sg_rule( group_id, source, 443, 'tcp', execute )

    sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-domino_fe_int' )
    if sg:
        group_id = sg[ 'GroupId' ]
        __add_sg_rule( group_id, source, 80, 'tcp', execute )
        __add_sg_rule( group_id, source, 443, 'tcp', execute )
        __add_sg_rule( group_id, source, 9000, 'tcp', execute )


def remove_whitelist_v4( vpc_id, stage_name, platform_namespace, source, execute = False ):
    if 'cidr' in source:
        cidr = source[ 'cidr' ]

        v1 = __get_kube_core_client()

        nic_svc = v1.read_namespaced_service( 'nginx-ingress-controller', platform_namespace )
        if __remove_action( cidr, nic_svc.spec.load_balancer_source_ranges ) and execute:
            v1.patch_namespaced_service( nic_svc.metadata.name, platform_namespace, nic_svc )

    sgs = get_security_groups( vpc_id )

    sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-general-admin' )
    group_id = sg[ 'GroupId' ]
    __remove_sg_rule( group_id, source, 22, 'tcp', execute )
    __remove_sg_rule( group_id, source, -1, 'icmp', execute )

    try:
        sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-domino_fe_ext_elb' )
        group_id = sg[ 'GroupId' ]
    except ( KeyError, TypeError ):
        sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-general-access' )
        group_id = sg[ 'GroupId' ]
    __remove_sg_rule( group_id, source, 80, 'tcp', execute )
    __remove_sg_rule( group_id, source, 443, 'tcp', execute )

    sg = __find_key_in_list( sgs, 'GroupName', stage_name + '-domino_fe_int' )
    if sg:
        group_id = sg[ 'GroupId' ]
        __remove_sg_rule( group_id, source, 80, 'tcp', execute )
        __remove_sg_rule( group_id, source, 443, 'tcp', execute )
        __remove_sg_rule( group_id, source, 9000, 'tcp', execute )


def __update_whitelist_v5(vpc_id, platform_namespace, source, execute, cidr_action: Callable, rules_action: Callable):
    if 'cidr' not in source:
        raise RuntimeError( 'NOT IMPLEMENTED: Adding Security Groups as a source is currently not implemented.' )

    cidr = source[ 'cidr' ]

    v1 = __get_kube_core_client()

    nic_svc: V1Service = v1.read_namespaced_service( 'nginx-ingress-controller', platform_namespace )
    if cidr_action(cidr, nic_svc.spec.load_balancer_source_ranges) and execute:
        v1.patch_namespaced_service( nic_svc.metadata.name, platform_namespace, nic_svc )

    sgs = get_security_groups(vpc_id)

    uid = nic_svc.metadata.uid.replace("-", "")[:-1]  # For some reason last character is excluded
    sg = __find_key_in_list(sgs, 'GroupName', "k8s-elb-a" + uid)

    group_id = sg['GroupId']
    rules_action(group_id, source, 80, 'tcp', execute=execute)
    rules_action(group_id, source, 443, 'tcp', execute=execute)


def add_whitelist_v5( vpc_id, platform_namespace, source, execute ):
    __update_whitelist_v5( vpc_id, platform_namespace, source, execute, __append_action, __add_sg_rule )


def remove_whitelist_v5( vpc_id, platform_namespace, source, execute ):
    __update_whitelist_v5( vpc_id, platform_namespace, source, execute, __remove_action, __remove_sg_rule )


def __get_boto3_ec2_client():
    if "AWS_REGION" in os.environ:
        client = boto3.client(
            'ec2',
            region_name=os.getenv('AWS_REGION'),
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        )
    else:
        instance_region = __get_metadata("placement/region")
        client = boto3.client( 'ec2', region_name=instance_region )
    return client


def __get_metadata(key: str) -> str:
    service_url = "http://169.254.169.254/latest"
    TOKEN_HEADER_TTL = "X-aws-ec2-metadata-token-ttl-seconds"
    TOKEN_HEADER = "X-aws-ec2-metadata-token"
    TOKEN_TTL_SECONDS = 21600  # Max TTL

    token_response = requests.put(
        f"{service_url}/api/token",
        headers={TOKEN_HEADER_TTL: str(TOKEN_TTL_SECONDS)},
        timeout=5.0,
    )
    if token_response.status_code != 200:
        token_response.raise_for_status()
    token = token_response.text

    response = requests.get(f"{service_url}/meta-data/{key}", headers={TOKEN_HEADER: token})
    response.raise_for_status()
    return response.text


def __get_kube_core_client():
    try:
        config.load_incluster_config()
    except config.ConfigException:
        try:
            config.load_kube_config()
        except config.ConfigException as ex:
            raise Exception("Could not configure kubernetes python client") from ex
    return client.CoreV1Api()


def __main():
    args = parse_args()
    if not args.vpc_id:
        if args.vpc:
            vpc_id = get_vpc_id( args.vpc )
            if vpc_id is None:
                print( 'Could not map VPC name %s to a VPC ID' % args.vpc )
                exit( 1 )
        else:
            # Get VPC ID from the instance metadata if we are running on an EC2 instance within the same VPC
            mac_id = __get_metadata("network/interfaces/macs/")
            vpc_id = __get_metadata(f"network/interfaces/macs/{mac_id}vpc-id")
        args.vpc_id = vpc_id

    if not args.platform_namespace:
        args.platform_namespace = args.stage_name + '-platform'

    domino = Domino( args.url )
    print( C.BOLD + C.HEADER + 'Detected Domino version: ' + C.ENDC + domino.version )

    if args.command in [ 'list-security-groups', 'list' ]:
        return list_security_groups( args.vpc_id )

    elif args.command in [ 'show-whitelist', 'show' ]:
        return show_whitelist( args.vpc_id )

    elif args.command in [ 'add-whitelist', 'add' ]:
        if domino.major == 3:
            add_whitelist_v3( args.vpc_id, args.stage_name, args.source, args.execute )
        elif domino.major == 4:
            add_whitelist_v4( args.vpc_id, args.stage_name, args.platform_namespace, args.source, args.execute )
        elif domino.major >= 5:
            add_whitelist_v5( args.vpc_id, args.platform_namespace, args.source, args.execute )

    elif args.command in [ 'remove-whitelist', 'remove' ]:
        if domino.major == 3:
            remove_whitelist_v3( args.vpc_id, args.stage_name, args.source, args.execute )
        elif domino.major == 4:
            remove_whitelist_v4( args.vpc_id, args.stage_name, args.platform_namespace, args.source, args.execute )
        elif domino.major >= 5:
            remove_whitelist_v5( args.vpc_id, args.platform_namespace, args.source, args.execute )


if __name__ == '__main__':
    __main()
