typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

typedef enum {
  error_program = -2,
  error_packet = -1,
  nomatch = false,
  match = true,
} match_result_type;

#define ETH_P_IP	0x0800
#define ETH_P_IPV6	0x86DD

#ifndef IPPROTO_TCP
#define IPPROTO_TCP	6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP	17
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6	58
#endif

#define ETH_HLEN	14
#define IPV4_HLEN	20
#define IPV6_HLEN	40
#define TCP_HLEN	20
#define UDP_HLEN	8
