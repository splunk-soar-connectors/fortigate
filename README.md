[comment]: # "Auto-generated SOAR connector documentation"
# FortiGate

Publisher: Splunk  
Connector Version: 2\.1\.8  
Product Vendor: Fortinet  
Product Name: FortiGate  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app supports a variety of containment and investigative actions on the FortiGate Firewall

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2017-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Explanation of Asset Configuration Parameters

The asset configuration parameters affect \[test connectivity\] and all the other actions of the
application. Below are the explanation and usage of all those parameters.

-   **Base URL -** The URL to connect to the Fortigate server.
-   **Username -** The username used for authentication.
-   **Password -** The password used for authentication.
-   **API Key -** The API Key used for authentication.
-   **Verify server certificate -** Enable or disable verify SSL certificates for HTTPS requests.
    The default value is false.
-   **Virtual domain (VDOM) -** It specifies the virtual domain to be used. It is an optional
    parameter. If no virtual domain is provided, it will use the one provided in the action
    parameters. And, if the virtual domain is not provided in the asset or action parameters, it
    will consider the virtual domain as root. Here, the value of VDOM is case-sensitive.

## App's Session-Based Authentication Workflow

-   **NOTE -** This authentication workflow requires the session-base authentication to be enabled
    on the Fortigate server environment.
-   Below are the workflow steps (that are automatically handled) for the authentication mechanism
    in all the actions.
    -   The authentication session gets enabled at the beginning of every action's execution by
        using the \[/logincheck\] API and the pair of username/password provided in the asset
        configuration parameters.
    -   This session and the associated cookies information (CSRF Token) is used to authenticate the
        further API requests to the Fortigate server in the action's workflow.
    -   Once, the action execution gets completed, the session created in step 1 is killed by using
        the \[/logout\] API.

## App's Token-Based Authentication Workflow

-   This app also supports API key based authentication.

-   Each API request can use an API token to be authenticated. An API token is generated by creating
    a new REST API admin on FortiGate GUI.

-   Please follow the steps mentioned in this
    [documentation](https://docs.fortinet.com/document/forticonverter/6.2.0/online-help/866905/connect-fortigate-device-via-api-token)
    to generate an API key.

-   The **Trusted Host** must be specified to ensure that your localhost can reach the FortiGate.
    For example, to restrict requests as coming from only 10.20.100.99, enter 10.20.100.99/32. The
    Trusted Host is created from the **Source Address** obtained from the below instruction.

-   **Determine your Source Address -**

      

    -   The source address is needed to ensure the API token can only be used from trusted hosts.
        This step can be skipped if the trusted host IP address is already known.
    -   On the FortiGate GUI, select the **Status** dashboard and locate the **Administrators**
        widget.
    -   Click **your-userid \> Show active administrator sessions** .
    -   The source address will be displayed under **Source Address** for **your-userid** .

-   Below are the workflow steps (that are automatically handled) for the authentication mechanism
    in all the actions.
    -   The API key is added in the params while making an API call for every action.

-   **NOTE -**
    -   If the password and API key both will be provided then API key will be given priority and
        Token-Based authentication workflow will be used.
    -   In case of login banners creating issue in the authentication, it is advisable to use a
        Token-Based authentication workflow to make the app work without any authentication
        interference.
    -   If a static IP address is not used in the "Trusted Hosts" field while generating an API key,
        then whenever the IP address changes, we will have to add it in the "Trusted Hosts" field.
        So it is advisable to use a static IP address.

## Explanation of Fortigate Actions' Parameters

-   ### Test Connectivity

    -   This action will test the connectivity of the Phantom server to the Fortigate instance by
        making an initial API call using the provided asset configuration parameters.
    -   The action validates the provided asset configuration parameters. Based on the API call
        response, the appropriate success and failure message will be displayed when the action gets
        executed.

-   ### Block IP

    -   **<u>Action Parameter</u> - IP**

        -   This parameter specifies the IP which is to be blocked. It is a required parameter.

          
          

    -   **<u>Action Parameter</u> - Policy**

        -   This parameter specifies the IPv4 policy to be used. It is a required parameter. All the
            available policies can be listed using the list policy action. The policy value should
            be present in the list of available policies.

          
          

    -   **<u>Action Parameter</u> - VDOM**

        -   This parameter specifies the virtual domain to be used. It is an optional parameter. If
            no virtual domain is provided, it will use the one provided in the asset configuration
            parameters. And, if the virtual domain is not provided in the asset or action
            parameters, it will consider the virtual domain as root. Here, the value of VDOM is
            case-sensitive.

          
          

    -   **<u>Action Functional Workflow</u>**
        -   The action uses a virtual domain parameter to search the policy in it. If no virtual
            domain is provided, it will use the one provided in the asset configuration parameters.
            And, if the virtual domain is not provided in the asset or action parameters, it will
            consider the virtual domain as root.
        -   If the policy name specified in the input parameters is not present in the virtual
            domain, the action run will be unsuccessful and it will return an appropriate error. If
            such policy is present in the list of IPv4 policies and it's "action" is "deny", it will
            search for the address entry. If the value of "action" is not "deny", the action run
            will be unsuccessful and it will return an appropriate error.
        -   If address entry is not present on the Fortigate server, it will create an address entry
            named ' **Phantom Addr \[ip_address\]\_\[net_bits\]** '. If address entry is present,
            action will search for the address in the destination of the policy specified.
        -   If the destination contains the provided address, the action will return an error. And
            if no such address is present in the destination, it will configure that particular
            address entry to the destination thereby successfully blocking the IP.

-   ### Unblock IP

    -   **<u>Action Parameter</u> - IP**

        -   This parameter specifies the IP which is to be unblocked. It is a required parameter.
            The IP value should be present in the list of blocked IPs otherwise action returns
            'already unblocked' success message.

          
          

    -   **<u>Action Parameter</u> - Policy**

        -   This parameter specifies the IPv4 policy to be used. It is a required parameter. All the
            available policies can be listed using the list policy action. The policy value should
            be present in the list of available policies.

          
          

    -   **<u>Action Parameter</u> - VDOM**

        -   This parameter specifies the virtual domain to be used. It is an optional parameter. If
            no virtual domain is provided, it will use the one provided in the asset configuration
            parameters. And, if the virtual domain is not provided in the asset or action
            parameters, it will consider the virtual domain as root. Here, the value of VDOM is
            case-sensitive.

          
          

    -   **<u>Action Functional Workflow</u>**
        -   The action uses a virtual domain parameter to search the policy in it. If no virtual
            domain is provided, it will use the one provided in the asset configuration parameters.
            And, if the virtual domain is not provided in the asset or action parameters, it will
            consider the virtual domain as root.
        -   If the policy name specified in the input parameters is not present in the virtual
            domain, the action run will be unsuccessful and it will return an appropriate error. If
            such policy is present in the list of IPv4 policies and it's "action" is "deny", it will
            search for the address entry. If the value of "action" is not "deny", the action run
            will be unsuccessful and it will return an appropriate error.
        -   If address entry is not present, the action will return an error. If address entry is
            present, action will search for the address in the destination of the policy specified.
        -   If the destination contains the provided address, the action will re-configure the
            policy by removing the address entry from the list of entries in the destination. If the
            address entry is not present in the list of entries in the destination, action will
            return successfully saying that the IP is already unblocked. The action does not delete
            the address entry from the system but removes its association from the destination of
            the particular policy.

-   ### List Policies

    -   **<u>Action Parameter</u> - VDOM**
        -   This parameter specifies the virtual domain to be used. It is an optional parameter. If
            no virtual domain is provided, it will use the one provided in the asset configuration
            parameters. And, if the virtual domain is not provided in the asset or action
            parameters, it will consider the virtual domain as root. Here, the value of VDOM is
            case-sensitive.
    -   **<u>Action Parameter</u> - Limit**
        -   This parameter is used to limit the number of policy results. The default value is 100.
            If the limit is not provided, it will fetch by default 100 policy results.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Fortigate server. Below are the default
ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a FortiGate asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | Device URL for e\.g\. https\://myforti\.contoso\.com
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**username** |  optional  | string | Username
**password** |  optional  | password | Password
**api\_key** |  optional  | password | API Key
**vdom** |  optional  | string | Virtual domain \(vdom\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[block ip](#action-block-ip) - Block an IP  
[unblock ip](#action-unblock-ip) - Unblock an IP  
[list policies](#action-list-policies) - List configured IPv4 policies  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'block ip'
Block an IP

Type: **contain**  
Read only: **False**

The action supports the following format for the <b>ip</b> parameter\:<ul><li>Simple IP\: For example 123\.123\.123\.123</li><li>IP, Subnet mask\: 123\.123\.0\.0 255\.255\.0\.0</li><li>CIDR Notation\: 123\.123\.0\.0/16</li></ul>This action uses a multistep approach to block IP\:<ul><li>Create an address entry named '<b>Phantom Addr \[ip\_address\]\_\[net\_bits\]</b>' if address not present, else directly configure address as the destination\.</li><li>Configure the address entered as the <i>destination</i> of the specified <b>policy name if the policy exists\. If the policy does not exist, action returns an error\- Policy probably does not exist in the given virtual domain\.</b>\.</li><li>The <b>policy</b> value expected is the IPv4 policy name\.</li></ul>The action will fail if\:<ul><li>The policy name is not found\. The action does not create a policy but edits it\.</li><li>Policy action is not a <b>deny</b>\.</li><li>Another value other than policy name is given as the <b>policy</b> such as policy ID\.</li><li>The policy name is not IPv4 policy\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to block | string |  `ip` 
**policy** |  required  | IPv4 policy name | string |  `fortigate policy` 
**vdom** |  optional  | Virtual domain | string |  `fortigate vdom` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.policy | string |  `fortigate policy` 
action\_result\.parameter\.vdom | string |  `fortigate vdom` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock ip'
Unblock an IP

Type: **correct**  
Read only: **False**

The action supports the following format for the <b>ip</b> parameter\:<ul><li>Simple IP\: For example 123\.123\.123\.123</li><li>IP, Subnet mask\: 123\.123\.0\.0 255\.255\.0\.0</li><li>CIDR Notation\: 123\.123\.0\.0/16</li></ul>This action uses a multistep approach to unblock IP\:<ul><li>Re\-configure the <b>policy</b> by removing the Address entry from the list of entries in the destination\. If the Address entry is not present in the list of entries in the destination, action will return successfully with message\- IP is already unblocked\.</li><li>The action does <i>not</i> delete the address entry from the system\.</li><li>If address entry is not found on the system, action will return an error\- Address does not exist\.</li><li>If the policy name is not found, action will return an error\.</li><li>The action will validate the Address entry name, and therefore will only unblock IPs that are added by the <b>block ip</b> action\.</li><li>If the policy name is not IPv4 policy, action will return an error\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to unblock | string |  `ip` 
**policy** |  required  | IPv4 policy name | string |  `fortigate policy` 
**vdom** |  optional  | Virtual domain | string |  `fortigate vdom` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.policy | string |  `fortigate policy` 
action\_result\.parameter\.vdom | string |  `fortigate vdom` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list policies'
List configured IPv4 policies

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vdom** |  optional  | Virtual domain | string |  `fortigate vdom` 
**limit** |  optional  | Maximum number of policies to be fetched \(Default\: 100\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.vdom | string |  `fortigate vdom` 
action\_result\.data\.\*\.action | string | 
action\_result\.data\.\*\.anti\-replay | string | 
action\_result\.data\.\*\.application\-list | string | 
action\_result\.data\.\*\.auth\-cert | string | 
action\_result\.data\.\*\.auth\-path | string | 
action\_result\.data\.\*\.auth\-redirect\-addr | string | 
action\_result\.data\.\*\.auto\-asic\-offload | string | 
action\_result\.data\.\*\.av\-profile | string | 
action\_result\.data\.\*\.block\-notification | string | 
action\_result\.data\.\*\.captive\-portal\-exempt | string | 
action\_result\.data\.\*\.capture\-packet | string | 
action\_result\.data\.\*\.casi\-profile | string | 
action\_result\.data\.\*\.cifs\-profile | string | 
action\_result\.data\.\*\.comments | string | 
action\_result\.data\.\*\.custom\-log\-fields | string | 
action\_result\.data\.\*\.delay\-tcp\-npu\-session | string | 
action\_result\.data\.\*\.delay\-tcp\-npu\-sessoin | string | 
action\_result\.data\.\*\.devices | string | 
action\_result\.data\.\*\.diffserv\-forward | string | 
action\_result\.data\.\*\.diffserv\-reverse | string | 
action\_result\.data\.\*\.diffservcode\-forward | string | 
action\_result\.data\.\*\.diffservcode\-rev | string | 
action\_result\.data\.\*\.disclaimer | string | 
action\_result\.data\.\*\.dlp\-sensor | string | 
action\_result\.data\.\*\.dnsfilter\-profile | string | 
action\_result\.data\.\*\.dsri | string | 
action\_result\.data\.\*\.dstaddr\-negate | string | 
action\_result\.data\.\*\.dstaddr\.\*\.name | string | 
action\_result\.data\.\*\.dstaddr\.\*\.q\_origin\_key | string | 
action\_result\.data\.\*\.dstintf\.\*\.name | string | 
action\_result\.data\.\*\.dstintf\.\*\.q\_origin\_key | string | 
action\_result\.data\.\*\.email\-collect | string | 
action\_result\.data\.\*\.emailfilter\-profile | string | 
action\_result\.data\.\*\.firewall\-session\-dirty | string | 
action\_result\.data\.\*\.fixedport | string | 
action\_result\.data\.\*\.fsso | string | 
action\_result\.data\.\*\.fsso\-agent\-for\-ntlm | string | 
action\_result\.data\.\*\.geoip\-anycast | string | 
action\_result\.data\.\*\.global\-label | string | 
action\_result\.data\.\*\.groups | string | 
action\_result\.data\.\*\.http\-policy\-redirect | string | 
action\_result\.data\.\*\.icap\-profile | string | 
action\_result\.data\.\*\.identity\-based\-route | string | 
action\_result\.data\.\*\.inbound | string | 
action\_result\.data\.\*\.inspection\-mode | string | 
action\_result\.data\.\*\.internet\-service | string | 
action\_result\.data\.\*\.internet\-service\-negate | string | 
action\_result\.data\.\*\.internet\-service\-src | string | 
action\_result\.data\.\*\.internet\-service\-src\-negate | string | 
action\_result\.data\.\*\.ippool | string | 
action\_result\.data\.\*\.ips\-sensor | string | 
action\_result\.data\.\*\.label | string | 
action\_result\.data\.\*\.learning\-mode | string | 
action\_result\.data\.\*\.logtraffic | string | 
action\_result\.data\.\*\.logtraffic\-start | string | 
action\_result\.data\.\*\.match\-vip | string | 
action\_result\.data\.\*\.match\-vip\-only | string | 
action\_result\.data\.\*\.name | string |  `fortigate policy` 
action\_result\.data\.\*\.nat | string | 
action\_result\.data\.\*\.natinbound | string | 
action\_result\.data\.\*\.natip | string | 
action\_result\.data\.\*\.natoutbound | string | 
action\_result\.data\.\*\.ntlm | string | 
action\_result\.data\.\*\.ntlm\-enabled\-browsers | string | 
action\_result\.data\.\*\.ntlm\-guest | string | 
action\_result\.data\.\*\.outbound | string | 
action\_result\.data\.\*\.per\-ip\-shaper | string | 
action\_result\.data\.\*\.permit\-any\-host | string | 
action\_result\.data\.\*\.permit\-stun\-host | string | 
action\_result\.data\.\*\.policyid | numeric | 
action\_result\.data\.\*\.poolname | string | 
action\_result\.data\.\*\.profile\-group | string | 
action\_result\.data\.\*\.profile\-protocol\-options | string | 
action\_result\.data\.\*\.profile\-type | string | 
action\_result\.data\.\*\.q\_origin\_key | numeric | 
action\_result\.data\.\*\.radius\-mac\-auth\-bypass | string | 
action\_result\.data\.\*\.redirect\-url | string | 
action\_result\.data\.\*\.replacemsg\-override\-group | string | 
action\_result\.data\.\*\.reputation\-direction | string | 
action\_result\.data\.\*\.reputation\-minimum | numeric | 
action\_result\.data\.\*\.rsso | string | 
action\_result\.data\.\*\.rtp\-addr | string | 
action\_result\.data\.\*\.rtp\-nat | string | 
action\_result\.data\.\*\.scan\-botnet\-connections | string | 
action\_result\.data\.\*\.schedule | string | 
action\_result\.data\.\*\.schedule\-timeout | string | 
action\_result\.data\.\*\.send\-deny\-packet | string | 
action\_result\.data\.\*\.service\-negate | string | 
action\_result\.data\.\*\.service\.\*\.name | string | 
action\_result\.data\.\*\.service\.\*\.q\_origin\_key | string | 
action\_result\.data\.\*\.session\-ttl | string | 
action\_result\.data\.\*\.spamfilter\-profile | string | 
action\_result\.data\.\*\.srcaddr\-negate | string | 
action\_result\.data\.\*\.srcaddr\.\*\.name | string | 
action\_result\.data\.\*\.srcaddr\.\*\.q\_origin\_key | string | 
action\_result\.data\.\*\.srcintf\.\*\.name | string | 
action\_result\.data\.\*\.srcintf\.\*\.q\_origin\_key | string | 
action\_result\.data\.\*\.ssh\-filter\-profile | string | 
action\_result\.data\.\*\.ssh\-policy\-redirect | string | 
action\_result\.data\.\*\.ssl\-mirror | string | 
action\_result\.data\.\*\.ssl\-mirror\-intf | string | 
action\_result\.data\.\*\.ssl\-ssh\-profile | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tcp\-mss\-receiver | numeric | 
action\_result\.data\.\*\.tcp\-mss\-sender | numeric | 
action\_result\.data\.\*\.tcp\-session\-without\-syn | string | 
action\_result\.data\.\*\.timeout\-send\-rst | string | 
action\_result\.data\.\*\.tos | string | 
action\_result\.data\.\*\.tos\-mask | string | 
action\_result\.data\.\*\.tos\-negate | string | 
action\_result\.data\.\*\.traffic\-shaper | string | 
action\_result\.data\.\*\.traffic\-shaper\-reverse | string | 
action\_result\.data\.\*\.users | string | 
action\_result\.data\.\*\.utm\-status | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.vlan\-cos\-fwd | numeric | 
action\_result\.data\.\*\.vlan\-cos\-rev | numeric | 
action\_result\.data\.\*\.vlan\-filter | string | 
action\_result\.data\.\*\.voip\-profile | string | 
action\_result\.data\.\*\.vpntunnel | string | 
action\_result\.data\.\*\.waf\-profile | string | 
action\_result\.data\.\*\.wanopt | string | 
action\_result\.data\.\*\.wanopt\-detection | string | 
action\_result\.data\.\*\.wanopt\-passive\-opt | string | 
action\_result\.data\.\*\.wanopt\-peer | string | 
action\_result\.data\.\*\.wanopt\-profile | string | 
action\_result\.data\.\*\.wccp | string | 
action\_result\.data\.\*\.webcache | string | 
action\_result\.data\.\*\.webcache\-https | string | 
action\_result\.data\.\*\.webfilter\-profile | string | 
action\_result\.data\.\*\.webproxy\-forward\-server | string | 
action\_result\.data\.\*\.webproxy\-profile | string | 
action\_result\.data\.\*\.wsso | string | 
action\_result\.summary\.total\_policies | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 