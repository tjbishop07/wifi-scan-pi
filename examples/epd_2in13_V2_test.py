#!/usr/bin/python
# -*- coding:utf-8 -*-
from PIL import Image, ImageDraw, ImageFont
import traceback
import time
from waveshare_epd import epd2in13_V2
import logging
import sys
import os

import signal
from scapy.all import *

picdir = os.path.join(os.path.dirname(
    os.path.dirname(os.path.realpath(__file__))), 'pic')
libdir = os.path.join(os.path.dirname(
    os.path.dirname(os.path.realpath(__file__))), 'lib')
if os.path.exists(libdir):
    sys.path.append(libdir)


logging.basicConfig(level=logging.DEBUG)
newiface = 'wlan1mon'
ap_list = []
font15 = ImageFont.truetype(os.path.join(picdir, 'Font.ttc'), 15)
font24 = ImageFont.truetype(os.path.join(picdir, 'Font.ttc'), 24)

epd = epd2in13_V2.EPD()
time_image = Image.new('1', (epd.height, epd.width), 255)
time_draw = ImageDraw.Draw(time_image)


def PacketHandler(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:
            if packet.addr2 not in ap_list:
                ap_list.append(packet.addr2)
                time_draw.rectangle((0, 0, 220, 105), fill=255)
                time_draw.text((0, 0), "Access Point MAC: %s with SSID: %s " % (
                    packet.addr2, packet.info), font=font15, fill=0)
                epd.displayPartial(epd.getbuffer(time_image))
                print("Access Point MAC: %s with SSID: %s " %
                      (packet.addr2, packet.info))

    # try:
    #     SRCMAC = packet[0].addr2
    #     DSTMAC = packet[0].addr
    #     BSSID = packet[0].addr3
    # except:
    #     print("Cannot read MAC address")

    # print('Got mAC')
    # # print(str(packet).encode("hex"))
    # # sys.exc_clear()

    # try:
    #     SSIDSize = packet[0][Dot11Elt].len
    #     SSID = packet[0][Dot11Elt].info
    # except:
    #     SSID = ""
    #     SSIDSize = 0

    # print('Analyzing packet: {0}'.format(str(packet[0].type)))
    # if packet[0].type == 0:
    #     ST = packet[0][Dot11].subtype
    #     print(str(SSID))
    #     print('Init epd...')
    #     epd = epd2in13_V2.EPD()
    #     epd.init(epd.FULL_UPDATE)

    #     image = Image.new('1', (epd.height, epd.width),
    #                       255)  # clear the screen
    #     draw = ImageDraw.Draw(image)
    #     draw.text((0, 0), str(SSID), font=font15, fill=0)
    #     epd.display(epd.getbuffer(image))

    #     if str(ST) == "8" and SSID != "" and DSTMAC.lower() == "ff:ff:ff:ff:ff:ff":
    #         p = packet[Dot11Elt]
    #         cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
    #                              "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
    #         channel = None
    #         crypto = set()
    #         while isinstance(p, Dot11Elt):
    #             try:
    #                 if p.ID == 3:
    #                     channel = ord(p.info)
    #                 elif p.ID == 48:
    #                     crypto.add("WPA2")
    #                 elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
    #                     crypto.add("WPA")
    #             except:
    #                 pass
    #             p = p.payload
    #         if not crypto:
    #             if 'privacy' in cap:
    #                 crypto.add("WEP")
    #             else:
    #                 crypto.add("OPN")
    #         if SRCMAC not in ssid_list.keys():
    #             # if '0050f204104a000110104400010210' in str(packet).encode("hex"):
    #             #	crypto.add("WPS")
    #             print("[+] New AP {0:5}\t{1:20}\t{2:20}\t{3:5}".format(
    #                 channel, BSSID, ' / '.join(crypto), SSID))
    #             ssid_list[SRCMAC] = SSID


try:

    global ssid_list
    ssid_list = {}
    logging.info("epd2in13_V2 Demo")

    epd.init(epd.FULL_UPDATE)
    epd.displayPartBaseImage(epd.getbuffer(time_image))
    epd.init(epd.PART_UPDATE)
    num = 0

    time_draw.rectangle((0, 0, 220, 105), fill=255)
    time_draw.text((0, 0), "Scanning...", font=font15, fill=0)
    epd.displayPartial(epd.getbuffer(time_image))

    logging.info("init and Clear")
    epd.init(epd.FULL_UPDATE)
    epd.Clear(0xFF)

    # logging.info("1.Drawing on the image...")
    # image = Image.new('1', (epd.height, epd.width),
    #                   255)  # 255: clear the frame
    # draw = ImageDraw.Draw(image)

    # #print("Setting up sniff optionsz...")
    # draw.text((120, 60), 'Starting wifi...', font=font15, fill=0)
    # #os.system('ifconfig ' + iface + ' down')
    # os.system('iwconfig ' + newiface + ' mode monitor')

    # draw.rectangle([(0, 0), (50, 50)], outline=0)
    # draw.rectangle([(55, 0), (100, 50)], fill=0)
    # draw.line([(0, 0), (50, 50)], fill=0, width=1)
    # draw.line([(0, 50), (50, 0)], fill=0, width=1)
    # draw.chord((10, 60, 50, 100), 0, 360, fill=0)
    # draw.ellipse((55, 60, 95, 100), outline=0)
    # draw.pieslice((55, 60, 95, 100), 90, 180, outline=0)
    # draw.pieslice((55, 60, 95, 100), 270, 360, fill=0)
    # draw.polygon([(110, 0), (110, 50), (150, 25)], outline=0)
    # draw.polygon([(190, 0), (190, 50), (150, 25)], fill=0)
    # draw.text((110, 90), u'微雪电子', font=font24, fill=0)
    # epd.display(epd.getbuffer(image))
    # time.sleep(2)

    # # read bmp file
    # logging.info("2.read bmp file...")
    # image = Image.open(os.path.join(picdir, '2in13.bmp'))
    # epd.display(epd.getbuffer(image))
    # time.sleep(2)

    # # read bmp file on window
    # logging.info("3.read bmp file on window...")
    # # epd.Clear(0xFF)
    # image1 = Image.new('1', (epd.height, epd.width),
    #                    255)  # 255: clear the frame
    # bmp = Image.open(os.path.join(picdir, '100x100.bmp'))
    # image1.paste(bmp, (2, 2))
    # epd.display(epd.getbuffer(image1))
    # time.sleep(2)

    sniff(iface=newiface, prn=PacketHandler)

    while (True):
        time_draw.rectangle((120, 80, 220, 105), fill=255)
        time_draw.text((120, 80), time.strftime(
            '%H:%M:%S'), font=font24, fill=0)
        epd.displayPartial(epd.getbuffer(time_image))
        num = num + 1
        if(num == 10):
            break

    logging.info("Clear...")
    epd.init(epd.FULL_UPDATE)
    epd.Clear(0xFF)

    logging.info("Goto Sleep...")
    epd.sleep()
    epd.Dev_exit()

except IOError as e:
    logging.info(e)

except KeyboardInterrupt:
    logging.info("ctrl + c:")
    epd2in13_V2.epdconfig.module_exit()
    exit()
