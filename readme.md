[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
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
-   Please follow the steps mentioned in this <a href="https://docs.fortinet.com/document/forticonverter/6.2.0/online-help/866905/connect-fortigate-device-via-api-token" target="_blank">documentation</a> 
    to generate an API key.
-   Below are the workflow steps (that are automatically handled) for the authentication mechanism
    in all the actions.
    -   The API key is added in the params while making an API call for every action.
-   **NOTE -** 
    -   If the password and API key both will be provided then API key will be given priority and 
        Token-Based authentication workflow will be used.
    -   In case of login banners creating issue in the authentication, it is advisable to use a 
        Token-Based authentication workflow to make the app work without any authentication 
        interference.
    -   If a static IP address is not used in the "Trusted Hosts" field while generating an API 
        key, then whenever the IP address changes, we will have to add it in the "Trusted Hosts" 
        field. So it is advisable to use a static IP address.

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
