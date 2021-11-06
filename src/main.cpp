// ESP8266 Simple sniffer
// 2018 Carve Systems LLC
// Angel Suarez-B Martin

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include "../lib/sdk_structs.h"
#include "../lib/ieee80211_structs.h"
#include "../lib/string_utils.h"
#include "../lib/sniffer.cpp"
#include "user_interface.h"
#include <WiFiUdp.h>


// Sniffing
#define TARGET "c0:c9:e3:49:9c:ff"
#define CHANNEL 8
#define TARGETMODE true
#define TARGETINTERVAL 100 // ms

// Upload Node
#define UPLOADWIFISSID "Wi-Fi - 224"
#define UPLOADWIFIPASS "21049510"
#define UPLOAD_IP IPAddress(192,168,0,198)
#define UPLOAD_PORT 5001
#define AGGREGATION 30 // MAX is 48
const int SIZE = 500; // RSSI(2byte) + SEQ(2bytes) = 4 bytes
// UDP
WiFiUDP UDP;

const int MAXTIME = 9999; // in seconds

boolean uploadMode = false;
// uint8_t from 0 to 255
// In ESP8266 Global variables use 31,663 bytes
int RSSI[SIZE]; // 2 bytes from 0 to something
// max seq number on sender is around 65520
unsigned int SEQ[SIZE]; // 2 bytes from 0 to 4294967295  {"s":,"r":} 11 + 10 + 10 = 31 bytes
int INDEX = 0;

void mac2str(const uint8_t *ptr, char *string) {
#ifdef MASKED
    sprintf(string, "XX:XX:XX:%02x:%02x:XX", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
#else
    sprintf(string, "%02x:%02x:%02x:%02x:%02x:%02x", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
#endif
    return;
}

void wifiConnect(const String &ssid, const String &pass) {// Begin WiFi
    WiFi.begin(ssid, pass); // Connect to the network
    // Connecting to WiFi...
    Serial.print("\nConnecting to ");
    Serial.print(ssid + "\n");
    // Loop continuously while WiFi is not connected
    while (WiFi.status() != WL_CONNECTED) {
        delay(100);
        Serial.print(".");
    }
    // Connected to WiFi
    Serial.println();
    Serial.print("Connected! IP address: ");
    Serial.println(WiFi.localIP());
}

void UDPSend(IPAddress ip, int port, char buff[]) {
    UDP.beginPacket(ip, port);
    UDP.write(buff);
    UDP.endPacket();
}



boolean isTarget(String s) {
    if (s.equals(TARGET))return true;
    return false;
}

// In this example, the packet handler function does all the parsing and output work.
// This is NOT ideal.
void wifi_sniffer_packet_handler(uint8_t *buff, uint16_t len) {
    // First layer: type cast the received buffer into our generic SDK structure
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *) buff;
    // Second layer: define pointer to where the actual 802.11 packet is within the structure
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *) ppkt->payload;
    // Third layer: define pointers to the 802.11 packet header and payload
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    const uint8_t *data = ipkt->payload;

    // Pointer to the frame control section within the packet header
    const wifi_header_frame_control_t *frame_ctrl = (wifi_header_frame_control_t *) &hdr->frame_ctrl;

    // Parse MAC addresses contained in packet header into human-readable strings
    char reciever[] = "00:00:00:00:00:00\0";
    char sender[] = "00:00:00:00:00:00\0";
    char filtering[] = "00:00:00:00:00:00\0";

    mac2str(hdr->addr1, reciever);
    mac2str(hdr->addr2, sender);
    mac2str(hdr->addr3, filtering);

    unsigned int sequence_nmb = hdr->sequence_ctrl;
    unsigned int time = max((int) (sequence_nmb / TARGETINTERVAL), 1);
    int rssi = ppkt->rx_ctrl.rssi;

    if (TARGETMODE) {
        if (isTarget(sender)) {
            boolean maxTimeReached = (time > MAXTIME);
            boolean maxMeasurementReached = INDEX >= SIZE;
            if (maxMeasurementReached) {
                uploadMode = true; // If we gathered enough data lets upload it
                return;
            } else if (sequence_nmb != 0) {
                Serial.printf("\n%d,%d",
                              (INDEX * 100) / SIZE, rssi);
                RSSI[INDEX] = rssi;
                SEQ[INDEX] = sequence_nmb;
                INDEX += 1;
            }
        }
    } /*
        Serial.printf("\nB %s , %s , %s ,%02d , %-28s E",
                      reciever,
                      sender,
                      filtering,
                      wifi_get_channel(),
                      ppkt->rx_ctrl.rssi,
                      wifi_pkt_type2str((wifi_promiscuous_pkt_type_t) frame_ctrl->type,
                                        (wifi_mgmt_subtypes_t) frame_ctrl->subtype)
        );
*/
    // max 200 3 chars for time-->
    // 2 chars for rssi
    // total 5 chars per meassurement


    /*   if (frame_ctrl->type == WIFI_PKT_MGMT && frame_ctrl->subtype == BEACON) {
           const wifi_mgmt_beacon_t *beacon_frame = (wifi_mgmt_beacon_t *) ipkt->payload;
           char ssid[32] = {0};
           if (beacon_frame->tag_length >= 32) {
               strncpy(ssid, beacon_frame->ssid, 31);
           } else {
               strncpy(ssid, beacon_frame->ssid, beacon_frame->tag_length);
           }
           String ssidstr(ssid);

       }*/


}


void setup() {
    // Serial setup
    Serial.begin(115200);
    Serial.println("Staring Sniffer");
    delay(10);
    wifi_set_channel(CHANNEL);

    // Wifi setup
    wifi_set_opmode(STATION_MODE);
    wifi_promiscuous_enable(0);
    WiFi.disconnect();

    // Set sniffer callback
    wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
    wifi_promiscuous_enable(1);

}

void loop() {
    if (uploadMode) {
        wifi_promiscuous_enable(0); // Disable sniffer mode
        WiFi.disconnect();
        wifiConnect(UPLOADWIFISSID, UPLOADWIFIPASS);
        upload(UPLOAD_IP, UPLOAD_PORT, AGGREGATION, INDEX, SEQ, RSSI, UDPSend);
        Serial.println("Data Sent! Rebooting now");
        uploadMode = false;
    }
    delay(10);
}

