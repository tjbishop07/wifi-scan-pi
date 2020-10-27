#!/usr/bin/python
# -*- coding:utf-8 -*-
from PIL import Image, ImageDraw, ImageFont
import traceback
import time
from waveshare_epd import epd2in13_V2
import logging
import sys
import os
import subprocess
import yaml
import psutil

picdir = os.path.join(os.path.dirname(
    os.path.dirname(os.path.realpath(__file__))), 'pic')
libdir = os.path.join(os.path.dirname(
    os.path.dirname(os.path.realpath(__file__))), 'lib')
if os.path.exists(libdir):
    sys.path.append(libdir)


logging.basicConfig(level=logging.DEBUG)
newiface = 'wlan1mon'
wifi_map_path = 'wifi_map.yaml'
ap_list = []
font12 = ImageFont.truetype(os.path.join(picdir, 'Font.ttc'), 12)
font15 = ImageFont.truetype(os.path.join(picdir, 'Font.ttc'), 15)
font24 = ImageFont.truetype(os.path.join(picdir, 'Font.ttc'), 24)

epd = epd2in13_V2.EPD()
time_image = Image.new('1', (epd.height, epd.width), 255)
time_draw = ImageDraw.Draw(time_image)


def parse_wifi_map(map_path):
    with open(map_path, 'r') as f:
        data = f.read()

    wifi_map = yaml.load(data)
    devices = set()
    associated_devices = set()

    if wifi_map is not None:
        for ssid in wifi_map:
            print('ssid = {}'.format(ssid))
            ssid_node = wifi_map[ssid]
            for bssid in ssid_node:
                print('\tbssid = {}'.format(bssid))
                bssid_node = ssid_node[bssid]
                if 'devices' in bssid_node:
                    for device in bssid_node['devices']:
                        devices |= {device}
                        if ssid != '~unassociated_devices':
                            associated_devices |= {device}
                            print('\t\tdevice (associated) = {}'.format(device))
                        else:
                            print('\t\tdevice = {}'.format(device))

        disk = psutil.disk_usage('/')
        # Divide from Bytes -> KB -> MB -> GB
        free = round(disk.free/1024.0/1024.0/1024.0, 1)
        total = round(disk.total/1024.0/1024.0/1024.0, 1)

        time_draw.rectangle((0, 0, 220, 125), fill=255)
        time_draw.text((0, 0), 'SSID count: {}'.format(
            len(wifi_map)), font=font15, fill=0)
        time_draw.text((0, 15), 'Associated device count: {}'.format(
            len(associated_devices)), font=font15, fill=0)
        time_draw.text((0, 35), 'Device count: {}'.format(
            len(devices)), font=font15, fill=0)
        time_draw.text((0, 100), '{}, CPU: {}, DISK: {}'.format(
            time.strftime('%H:%M:%S'), str(psutil.cpu_percent()) + '%', str(free) + 'GB free / ' + str(total) + 'GB total ( ' + str(disk.percent) + '% )'), font=font12, fill=0)
        epd.displayPartial(epd.getbuffer(time_image))
        print('\n\nSSID count: {}, Associated device count: {}, Device count: {}'.format(
            len(wifi_map), len(associated_devices), len(devices)))


try:

    global ssid_list
    ssid_list = {}
    logging.info("init and Clear")
    epd.init(epd.FULL_UPDATE)
    epd.Clear(0xFF)
    epd.init(epd.FULL_UPDATE)
    epd.displayPartBaseImage(epd.getbuffer(time_image))
    epd.init(epd.PART_UPDATE)
    num = 0

    time_draw.rectangle((0, 0, 220, 105), fill=255)
    time_draw.text((0, 0), "Loading...", font=font15, fill=0)
    epd.displayPartial(epd.getbuffer(time_image))
    #os.system('trackerjacker -i wlan1 --map')
    #logging.info("Launching tJ...")
    #process = subprocess.Popen(['trackerjacker', '-i', 'wlan1', '--map'])
    #stdout, stderr = process.communicate()

    #cmd = "trackerjacker -i wlan1 --map"
    #p = subprocess.run(cmd, shell=True)

    while (True):

        parse_wifi_map(wifi_map_path)

        # time_draw.rectangle((120, 80, 220, 105), fill=255)
        # time_draw.text((120, 80), time.strftime(
        #    '%H:%M:%S'), font=font24, fill=0)
        # epd.displayPartial(epd.getbuffer(time_image))
        # num = num + 1
        # if(num == 10):
        #     break

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
