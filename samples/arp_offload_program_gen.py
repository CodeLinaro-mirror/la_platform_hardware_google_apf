import argparse

PROGRAM_TEMPLATE = "750010{}08060001080006040002AA300E3CAA0FBA06AA09BA07AA08BA086A01BA09120C84006F08066A0EA30206000108000604032B12147A27017A020203301A1C820200032D68A30206FFFFFFFFFFFF020E1A267E00000002{}032C020B1A267E00000002{}032CAB24003CCA0606CB0306CB090ACB0306C6{}CA0606CA1C04AA0A3A12AA1AAA25FFFF032F020D120C84001708000A1782100612149C00091FFFAB0D2A10820207032A02117C000E86DD68A30206FFFFFFFFFFFF021603190A1482020002187A023A02120A36820285031F8216886A26A2020FFF020000000000000000000000000003200214"

def generate_apf_program(mac_raw, ip_raw):
    """
    Generates an APF program that support ARP offload

    Args:
        mac_raw (str): The MAC address (colon-separated hexadecimal values).
        ip_raw (str): The IPv4 address (dot-separated decimal values).

    Returns:
        str: The generated APF program hex string.
    """
    mac_list = mac_raw.split(":")
    ip_list = ip_raw.split(".")

    ip_addr = "".join(["{:02x}".format(int(i)) for i in ip_list])
    mac_addr = "".join(mac_list)

    return PROGRAM_TEMPLATE.format(mac_addr, ip_addr, ip_addr, ip_addr)


def main():
    parser = argparse.ArgumentParser(description="Generate an ARP offload APF program.")
    parser.add_argument("mac", help="The DUT's MAC address (e.g., '00:11:22:33:44:55')")
    parser.add_argument("ip", help="The DUT's IPv4 address (e.g., '192.168.1.100')")
    args = parser.parse_args()

    out_program = generate_apf_program(args.mac, args.ip)
    print("APF Program:\n", out_program)


if __name__ == '__main__':
    main()
