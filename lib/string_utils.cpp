#include "sdk_structs.h"
#include "ieee80211_structs.h"

// Uncomment to enable MAC address masking
//#define MASKED


// Output info to serial
/*Serial.printf("\n%s | %s | %s | %u | %02d | %u | %u(%-2u) | %-28s | %u | %u | %u | %u | %u | %u | %u | %u | ",
  reciever,
  sender,
  filtering,
  wifi_get_channel(),
  ppkt->rx_ctrl.rssi,
  frame_ctrl->protocol,
  frame_ctrl->type,
  frame_ctrl->subtype,
  wifi_pkt_type2str((wifi_promiscuous_pkt_type_t)frame_ctrl->type, (wifi_mgmt_subtypes_t)frame_ctrl->subtype),
  frame_ctrl->to_ds,
  frame_ctrl->from_ds,
  frame_ctrl->more_frag,
  frame_ctrl->retry,
  frame_ctrl->pwr_mgmt,
  frame_ctrl->more_data,
  frame_ctrl->wep,
  frame_ctrl->strict);
// Print ESSID if beacon
if (frame_ctrl->type == WIFI_PKT_MGMT && frame_ctrl->subtype == BEACON)
{
  const wifi_mgmt_beacon_t *beacon_frame = (wifi_mgmt_beacon_t*) ipkt->payload;
  char ssid[32] = {0};
  if (beacon_frame->tag_length >= 32)
  {
    strncpy(ssid, beacon_frame->ssid, 31);
  }
  else
  {
    strncpy(ssid, beacon_frame->ssid, beacon_frame->tag_length);
  }
  Serial.printf("%s", ssid);
}*/


//Returns a human-readable string from a binary MAC address.
//If MASKED is defined, it masks the output with XX
void mac2str(const uint8_t *ptr, char *string) {
#ifdef MASKED
    sprintf(string, "XX:XX:XX:%02x:%02x:XX", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
#else
    sprintf(string, "%02x:%02x:%02x:%02x:%02x:%02x", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
#endif
    return;
}

// According to the SDK documentation, the packet type can be inferred from the
// size of the buffer. We are ignoring this information and parsing the type-subtype
// from the packet header itself. Still, this is here for reference.
wifi_promiscuous_pkt_type_t packet_type_parser(uint16_t len) {
    switch (len) {
        // If only rx_ctrl is returned, this is an unsupported packet
        case sizeof(wifi_pkt_rx_ctrl_t):
            return WIFI_PKT_MISC;

            // Management packet
        case sizeof(wifi_pkt_mgmt_t):
            return WIFI_PKT_MGMT;

            // Data packet
        default:
            return WIFI_PKT_DATA;
    }
}


//Parses 802.11 packet type-subtype pair into a human-readable string
const char *wifi_pkt_type2str(wifi_promiscuous_pkt_type_t type, wifi_mgmt_subtypes_t subtype) {
    switch (type) {
        case WIFI_PKT_MGMT:
            switch (subtype) {
                case ASSOCIATION_REQ:
                    return "Mgmt: Association request";
                case ASSOCIATION_RES:
                    return "Mgmt: Association response";
                case REASSOCIATION_REQ:
                    return "Mgmt: Reassociation request";
                case REASSOCIATION_RES:
                    return "Mgmt: Reassociation response";
                case PROBE_REQ:
                    return "Mgmt: Probe request";
                case PROBE_RES:
                    return "Mgmt: Probe response";
                case BEACON:
                    return "Mgmt: Beacon frame";
                case ATIM:
                    return "Mgmt: ATIM";
                case DISASSOCIATION:
                    return "Mgmt: Dissasociation";
                case AUTHENTICATION:
                    return "Mgmt: Authentication";
                case DEAUTHENTICATION:
                    return "Mgmt: Deauthentication";
                case ACTION:
                    return "Mgmt: Action";
                case ACTION_NACK:
                    return "Mgmt: Action no ack";
                default:
                    return "Mgmt: Unsupported/error";
            }

        case WIFI_PKT_CTRL:
            return "Control";

        case WIFI_PKT_DATA:
            return "Data";

        default:
            return "Unsupported/error";
    }
}

