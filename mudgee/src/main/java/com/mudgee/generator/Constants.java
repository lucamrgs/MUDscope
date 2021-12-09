/*
 * Copyright (c) 2018, UNSW. (https://www.unsw.edu.au/) All Rights Reserved.
 *
 * UNSW. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.mudgee.generator;

public class Constants {

    public static final String DHCP_PORT = "67";
    public static final String DHCPV6_PORT = "547";
    public static final String DNS_PORT = "53";
    public static final String NTP_PORT = "123";
    public static final String TCP_PROTO = "6";
    public static final String UDP_PROTO = "17";
    public static final String IGMP_PROTO = "2";
    public static final String ICMP_PROTO = "1";
    public static final String IPV6_ICMP_PROTO = "58";
    public static final String ETH_TYPE_IPV4 = "0x0800";
    public static final String ETH_TYPE_IPV6 = "0x86dd";
    public static final String ETH_TYPE_ARP = "0x0806";
    public static final String ETH_TYPE_EAPOL = "0x888e";

    public static final String ICMP_ECHO_TYPE = "8";
    public static final String ICMP_ECHO_REPLY_TYPE = "0";
    public static final String DEFAULT_ICMP_CODE = "0";

    public static final int COMMON_FLOW_PRIORITY = 1000;
    public static final int D2G_FIXED_FLOW_PRIORITY = 850;
    public static final int D2G_FIXED_FLOW_INITIALIZED_PRIORITY = 855;
    public static final int D2G_DYNAMIC_FLOW_PRIORITY = 810;
    public static final int D2G_PRIORITY = 800;
    public static final int G2D_FIXED_FLOW_INITIALIZED_PRIORITY = 755;
    public static final int G2D_FIXED_FLOW_PRIORITY = 750;
    public static final int G2D_DYNAMIC_FLOW_PRIORITY = 710;
    public static final int G2D_PRIORITY = 700;
    public static final int L2D_FIXED_FLOW_PRIORITY = 650;
    public static final int L2D_FIXED_FLOW_INIALIZED_PRIORITY = 655;
    public static final int L2D_DYNAMIC_FLOW_PRIORITY = 610;
    public static final int L2D_PRIORITY = 600;
    public static final int SKIP_FLOW_PRIORITY = 400;
    public static final int SKIP_FLOW_HIGHER_PRIORITY = 950;
    public static final int MULTICAST_BROADCAST_PRIORITY = 1300;
    public static final int ALL_DEVICE_COMMON_PRIORITY = 1400;

    public static final String BROADCAST_MAC = "ff:ff:ff:ff:ff:ff";
    public static final String BROADCAST_IP = "255.255.255.255";
    public static final String HOPOPT_PROTO = "0";
    public static final String LINK_LOCAL_ALL_NODE = "ff02";
    public static final String LINK_LOCAL_MULTICAST_IP_RANGE = "ff00::/8";

}
