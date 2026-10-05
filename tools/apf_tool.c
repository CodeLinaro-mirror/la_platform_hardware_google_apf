/*
 * apf_tool.c
 *
 * A vendor-agnostic command-line tool for interacting with the net-apf
 * generic netlink interface. This tool can be used to query APF info,
 * manage APF lifecycle and RAM, install APF bytecode programs, read/write APF
 * RAM, and configure hardware fast path on any compliant network device.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "net_apf.h"

// ----- HELPER FUNCTIONS -----

// Converts a hex string like "010407" to a byte array
static int hex_str_to_bytes(const char *hex_str, unsigned char *byte_array, size_t max_len) {
    size_t len = strlen(hex_str);
    if (len & 1) return -1;

    size_t byte_count = 0;
    for (size_t i = 0; i < len; i += 2) {
        if (byte_count >= max_len) return -1;
        if (!isxdigit(hex_str[i]) || !isxdigit(hex_str[i+1])) return -1;

        sscanf(&hex_str[i], "%2hhx", &byte_array[byte_count]);
        byte_count++;
    }
    return byte_count;
}

// Parses a hex string into a dynamically allocated byte array.
// Returns byte length on success, or -1 on error. Caller must free(*out_bytes).
static int parse_hex_alloc(const char *hex_str, unsigned char **out_bytes) {
    size_t hex_len = strlen(hex_str);
    if (hex_len & 1) return -1;

    size_t byte_len = hex_len / 2;
    unsigned char *bytes = malloc(byte_len ? byte_len : 1);
    if (!bytes) return -1;

    int ret = hex_str_to_bytes(hex_str, bytes, byte_len);
    if (ret < 0) {
        free(bytes);
        return -1;
    }
    *out_bytes = bytes;
    return ret;
}

static int parse_mac(const char *str, unsigned char *mac) {
    struct ether_addr *ea = ether_aton(str);
    if (ea) {
        memcpy(mac, ea->ether_addr_octet, ETH_ALEN);
        return 0;
    }
    if (strlen(str) == 12 && hex_str_to_bytes(str, mac, ETH_ALEN) == ETH_ALEN) {
        return 0;
    }
    return -1;
}

// Helper to allocate and initialize a net-apf Netlink message with IFINDEX.
static struct nl_msg *alloc_apf_msg(int family_id, int if_index, int cmd, int flags) {
    struct nl_msg *msg = nlmsg_alloc_size(65536);
    if (!msg) return NULL;

    if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0,
                     NLM_F_REQUEST | flags, cmd, NET_APF_FAMILY_VERSION)) {
        nlmsg_free(msg);
        return NULL;
    }
    if (nla_put_u32(msg, NET_APF_A_IFINDEX, if_index) < 0) {
        nlmsg_free(msg);
        return NULL;
    }
    return msg;
}

static int send_and_recv(struct nl_sock *sock, struct nl_msg *msg) {
    int ret = nl_send_auto(sock, msg);
    if (ret >= 0) ret = nl_recvmsgs_default(sock);
    return ret;
}

// ----- NETLINK CALLBACKS FOR PARSING REPLIES -----

static int parse_get_info_reply(struct nl_msg *msg, __unused void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NET_APF_A_MAX + 1];

    if (nla_parse(tb, NET_APF_A_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL) < 0) {
        fprintf(stderr, "Failed to parse netlink attributes.\n");
        return NL_SKIP;
    }

    printf("APF Info:\n");
    if (tb[NET_APF_A_INFO_VERSION])
        printf("  Version: %u\n", nla_get_u32(tb[NET_APF_A_INFO_VERSION]));
    if (tb[NET_APF_A_INFO_CHIP_ID])
        printf("  Chip ID: %u\n", nla_get_u32(tb[NET_APF_A_INFO_CHIP_ID]));
    if (tb[NET_APF_A_INFO_TOTAL_RAM])
        printf("  Total RAM: %u bytes\n", nla_get_u32(tb[NET_APF_A_INFO_TOTAL_RAM]));
    if (tb[NET_APF_A_INFO_USED_RAM])
        printf("  Used RAM: %u bytes\n", nla_get_u32(tb[NET_APF_A_INFO_USED_RAM]));
    if (tb[NET_APF_A_INFO_OVERHEAD])
        printf("  Overhead: %u bytes\n", nla_get_u32(tb[NET_APF_A_INFO_OVERHEAD]));
    if (tb[NET_APF_A_INFO_GRANULARITY])
        printf("  Granularity: %u bytes\n", nla_get_u32(tb[NET_APF_A_INFO_GRANULARITY]));
    return NL_OK;
}

static int parse_get_ram_size_reply(struct nl_msg *msg, __unused void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NET_APF_A_MAX + 1];

    if (nla_parse(tb, NET_APF_A_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL) < 0) {
        fprintf(stderr, "Failed to parse netlink attributes.\n");
        return NL_SKIP;
    }

    if (tb[NET_APF_A_RAM_SIZE])
        printf("Allocated RAM Size: %u bytes\n", nla_get_u32(tb[NET_APF_A_RAM_SIZE]));
    return NL_OK;
}

static int parse_read_reply(struct nl_msg *msg, __unused void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NET_APF_A_MAX + 1];

    if (nla_parse(tb, NET_APF_A_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL) < 0) {
        fprintf(stderr, "Failed to parse netlink attributes.\n");
        return NL_SKIP;
    }

    if (tb[NET_APF_A_DATA]) {
        unsigned char *data = nla_data(tb[NET_APF_A_DATA]);
        int len = nla_len(tb[NET_APF_A_DATA]);
        printf("APF RAM Data (%d bytes):\n", len);
        for (int i = 0; i < len; i++) {
            printf("%02x", data[i]);
        }
        printf("\n");
    } else {
        printf("No data received.\n");
    }
    return NL_OK;
}

static void print_usage(const char *name) {
    fprintf(stderr, "Usage: %s <iface> <command> [args...]\n\n", name);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  get_info                            Query APF and device info\n");
    fprintf(stderr, "  set_id <id>                         Set chip-level APF instance identifier\n");
    fprintf(stderr, "  enable <ram_size>                   Enable APF with requested RAM size\n");
    fprintf(stderr, "  get_ram_size                        Query allocated RAM size\n");
    fprintf(stderr, "  read [offset [len]]                 Read APF RAM (default: all allocated RAM)\n");
    fprintf(stderr, "  write <hex_data> [offset]           Write to APF RAM at offset, or install program if no offset\n");
    fprintf(stderr, "  disable                             Disable APF and free allocated state\n");
    fprintf(stderr, "  set_fast_path <mac> [vlan-tag=<n>] [ucast-addr4=<ip>] [enable-ipv6]\n");
    fprintf(stderr, "                                      Configure hardware fast path filtering\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s wlan0 get_info\n", name);
    fprintf(stderr, "  %s wlan0 set_id 1\n", name);
    fprintf(stderr, "  %s wlan0 enable 4096\n", name);
    fprintf(stderr, "  %s wlan0 get_ram_size\n", name);
    fprintf(stderr, "  %s wlan0 read\n", name);
    fprintf(stderr, "  %s wlan0 read 0 1024\n", name);
    fprintf(stderr, "  %s wlan0 write 00\n", name);
    fprintf(stderr, "  %s wlan0 write deadbeef 0\n", name);
    fprintf(stderr, "  %s wlan0 disable\n", name);
    fprintf(stderr, "  %s wlan0 set_fast_path 02:00:00:00:00:01 ucast-addr4=192.168.1.100 enable-ipv6\n", name);
}

// ----- MAIN -----

int main(int argc, char **argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *if_name = argv[1];
    const char *command = argv[2];
    int ret = 0;

    int if_index = if_nametoindex(if_name);
    if (if_index == 0) {
        perror("if_nametoindex");
        return 1;
    }

    struct nl_sock *sock = nl_socket_alloc();
    if (!sock) return -ENOMEM;

    nl_socket_set_msg_buf_size(sock, 65536);
    nl_socket_enable_msg_peek(sock);

    if (genl_connect(sock) < 0) {
        fprintf(stderr, "Failed to connect to generic netlink.\n");
        ret = -1; goto cleanup_sock;
    }

    int family_id = genl_ctrl_resolve(sock, NET_APF_FAMILY_NAME);
    if (family_id < 0) {
        fprintf(stderr, "Failed to resolve %s family: %s. Is the kernel module loaded?\n",
                NET_APF_FAMILY_NAME, nl_geterror(family_id));
        ret = -1; goto cleanup_sock;
    }

    struct nl_msg *msg = NULL;

    if (strcmp(command, "get_info") == 0) {
        msg = alloc_apf_msg(family_id, if_index, NET_APF_CMD_GET_INFO, 0);
        if (!msg) { ret = -ENOMEM; goto cleanup_sock; }

        nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, parse_get_info_reply, NULL);
        ret = send_and_recv(sock, msg);
        if (ret < 0) fprintf(stderr, "Failed to query APF info: %s\n", nl_geterror(ret));

    } else if (strcmp(command, "set_id") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: 'set_id' command requires an id.\n");
            print_usage(argv[0]);
            ret = -1; goto cleanup_sock;
        }
        uint32_t id = (uint32_t)strtoul(argv[3], NULL, 0);

        msg = alloc_apf_msg(family_id, if_index, NET_APF_CMD_SET_ID, NLM_F_ACK);
        if (!msg) { ret = -ENOMEM; goto cleanup_sock; }

        nla_put_u32(msg, NET_APF_A_INFO_CHIP_ID, id);

        ret = send_and_recv(sock, msg);
        if (ret < 0) {
            fprintf(stderr, "Failed to set APF ID: %s\n", nl_geterror(ret));
        } else {
            printf("Successfully set APF chip ID to %u.\n", id);
        }

    } else if (strcmp(command, "enable") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: 'enable' command requires ram_size.\n");
            print_usage(argv[0]);
            ret = -1; goto cleanup_sock;
        }
        int ram_size = atoi(argv[3]);
        if (ram_size <= 0) {
            fprintf(stderr, "Error: ram_size must be positive.\n");
            ret = -1; goto cleanup_sock;
        }

        msg = alloc_apf_msg(family_id, if_index, NET_APF_CMD_ENABLE, NLM_F_ACK);
        if (!msg) { ret = -ENOMEM; goto cleanup_sock; }

        nla_put_u32(msg, NET_APF_A_RAM_SIZE, (uint32_t)ram_size);

        ret = send_and_recv(sock, msg);
        if (ret < 0) {
            fprintf(stderr, "Failed to enable APF: %s\n", nl_geterror(ret));
        } else {
            printf("Successfully enabled APF with %d bytes RAM.\n", ram_size);
        }

    } else if (strcmp(command, "get_ram_size") == 0) {
        msg = alloc_apf_msg(family_id, if_index, NET_APF_CMD_GET_RAM_SIZE, 0);
        if (!msg) { ret = -ENOMEM; goto cleanup_sock; }

        nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, parse_get_ram_size_reply, NULL);
        ret = send_and_recv(sock, msg);
        if (ret < 0) fprintf(stderr, "Failed to query APF RAM size: %s\n", nl_geterror(ret));

    } else if (strcmp(command, "read") == 0) {
        msg = alloc_apf_msg(family_id, if_index, NET_APF_CMD_READ, 0);
        if (!msg) { ret = -ENOMEM; goto cleanup_sock; }

        if (argc >= 4) nla_put_u32(msg, NET_APF_A_OFFSET, (uint32_t)atoi(argv[3]));
        if (argc >= 5) nla_put_u32(msg, NET_APF_A_DATA_LEN, (uint32_t)atoi(argv[4]));

        nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, parse_read_reply, NULL);
        ret = send_and_recv(sock, msg);
        if (ret < 0) fprintf(stderr, "Failed to read APF RAM: %s\n", nl_geterror(ret));

    } else if (strcmp(command, "write") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: 'write' command requires hex data string.\n");
            print_usage(argv[0]);
            ret = -1; goto cleanup_sock;
        }
        unsigned char *data_bytes = NULL;
        int data_len = parse_hex_alloc(argv[3], &data_bytes);
        if (data_len < 0) {
            fprintf(stderr, "Error: Invalid hex data string.\n");
            ret = -1; goto cleanup_sock;
        }

        msg = alloc_apf_msg(family_id, if_index, NET_APF_CMD_WRITE, NLM_F_ACK);
        if (!msg) { free(data_bytes); ret = -ENOMEM; goto cleanup_sock; }

        nla_put(msg, NET_APF_A_DATA, data_len, data_bytes);
        if (argc >= 5) nla_put_u32(msg, NET_APF_A_OFFSET, (uint32_t)atoi(argv[4]));
        free(data_bytes);

        ret = send_and_recv(sock, msg);
        if (ret < 0) {
            fprintf(stderr, "Failed to write APF RAM: %s\n", nl_geterror(ret));
        } else {
            printf("Successfully wrote %d bytes to APF RAM.\n", data_len);
        }

    } else if (strcmp(command, "disable") == 0) {
        msg = alloc_apf_msg(family_id, if_index, NET_APF_CMD_DISABLE, NLM_F_ACK);
        if (!msg) { ret = -ENOMEM; goto cleanup_sock; }

        ret = send_and_recv(sock, msg);
        if (ret < 0) {
            fprintf(stderr, "Failed to disable APF: %s\n", nl_geterror(ret));
        } else {
            printf("Successfully disabled APF.\n");
        }

    } else if (strcmp(command, "set_fast_path") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: 'set_fast_path' requires <mac>\n");
            print_usage(argv[0]);
            ret = -1; goto cleanup_sock;
        }
        unsigned char mac[ETH_ALEN];
        if (parse_mac(argv[3], mac) < 0) {
            fprintf(stderr, "Error: Invalid MAC address '%s'\n", argv[3]);
            ret = -1; goto cleanup_sock;
        }

        msg = alloc_apf_msg(family_id, if_index, NET_APF_CMD_SET_FAST_PATH, NLM_F_ACK);
        if (!msg) { ret = -ENOMEM; goto cleanup_sock; }

        nla_put(msg, NET_APF_A_FP_UCAST_MAC, ETH_ALEN, mac);
        for (int i = 4; i < argc; i++) {
            struct in_addr ip4_addr;
            if (strncmp(argv[i], "vlan-tag=", 9) == 0) {
                nla_put_u16(msg, NET_APF_A_FP_VLAN_TAG, (uint16_t)atoi(argv[i] + 9));
            } else if (strncmp(argv[i], "ucast-addr4=", 12) == 0 &&
                       inet_pton(AF_INET, argv[i] + 12, &ip4_addr) == 1) {
                nla_put_u32(msg, NET_APF_A_FP_UCAST_ADDR4, ip4_addr.s_addr);
            } else if (strcmp(argv[i], "enable-ipv6") == 0) {
                nla_put_flag(msg, NET_APF_A_FP_ENABLE_IPV6);
            } else {
                fprintf(stderr, "Error: Invalid argument '%s'\n", argv[i]);
                nlmsg_free(msg);
                ret = -1; goto cleanup_sock;
            }
        }

        ret = send_and_recv(sock, msg);
        if (ret < 0) {
            fprintf(stderr, "Failed to configure fast path: %s\n", nl_geterror(ret));
        } else {
            printf("Successfully configured APF fast path.\n");
        }

    } else {
        fprintf(stderr, "Error: Unknown command '%s'\n", command);
        print_usage(argv[0]);
        ret = -1;
    }

    nlmsg_free(msg);
cleanup_sock:
    nl_socket_free(sock);
    return ret < 0 ? 1 : 0;
}