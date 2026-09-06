#!/usr/bin/env python3
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))

from arp_guard import (ARPFrame, ARPSimulator, ARPGuardDecider,
                       ARPGuardEngine, mac_to_bytes, ip_to_bytes,
                       run_pipe_harness)


class ARPFrameTest(unittest.TestCase):
    def test_roundtrip_parse(self):
        f = ARPFrame.reply('00:11:22:33:44:55', '192.0.2.1',
                           '00:00:00:00:00:00', '192.0.2.50')
        data = f.build()
        self.assertEqual(len(data), 42)
        p = ARPFrame.parse(data)
        self.assertEqual(p.op, 2)
        self.assertEqual(mac_to_bytes('00:11:22:33:44:55'), p.sha)
        self.assertEqual(ip_to_bytes('192.0.2.1'), p.spa)
        self.assertEqual(ip_to_bytes('192.0.2.50'), p.tpa)

    def test_parse_rejects_non_arp(self):
        with self.assertRaises(ValueError):
            ARPFrame.parse(b'\x00' * 42)


class DeciderTest(unittest.TestCase):
    def setUp(self):
        self.decider = ARPGuardDecider('192.0.2.1', '00:11:22:33:44:55')

    def test_legit_gateway_reply_not_flagged(self):
        data = ARPSimulator.legitimate_gateway_reply()
        result = self.decider.process(ARPFrame.parse(data))
        self.assertIsNone(result)
        self.assertEqual(self.decider.stats['suspicious'], 0)

    def test_spoof_gateway_reply_flagged(self):
        data = ARPSimulator.spoofed_gateway_reply()
        result = self.decider.process(ARPFrame.parse(data))
        self.assertIsNotNone(result)
        self.assertEqual(result['event'], 'SPOOF')
        self.assertEqual(result['expected_mac'], '00:11:22:33:44:55')
        self.assertEqual(result['observed_mac'], '00:11:22:33:44:66')

    def test_threshold_blocks_after_two(self):
        for _ in range(2):
            data = ARPSimulator.spoofed_gateway_reply()
            result = self.decider.process(ARPFrame.parse(data))
        self.assertIsNotNone(result)
        self.assertTrue(result['blocked'])


class EngineHarnessTest(unittest.TestCase):
    def test_harness_passes(self):
        rc = run_pipe_harness({'gateway_ip': '192.0.2.1',
                               'gateway_mac': '00:11:22:33:44:55',
                               'block_threshold': 2})
        self.assertEqual(rc, 0)


class DuplicateIPTests(unittest.TestCase):
    def test_duplicate_ip_detected(self):
        d = ARPGuardDecider('192.0.2.1', '00:11:22:33:44:55')
        g = ARPGuardEngine(decider=d)
        g.feed_bytes(ARPSimulator.legitimate_gateway_reply())
        host = ARPFrame.reply('00:aa:bb:cc:dd:ee', '192.0.2.50',
                              '00:00:00:00:00:00', '192.0.2.51').build()
        r1 = g.feed_bytes(host)
        self.assertIsNone(r1)
        host2 = ARPFrame.reply('00:aa:bb:cc:dd:ff', '192.0.2.50',
                               '00:00:00:00:00:00', '192.0.2.51').build()
        r2 = g.feed_bytes(host2)
        self.assertEqual(r2['event'], 'DUPLICATE')
        self.assertEqual(r2['ip'], '192.0.2.50')


if __name__ == '__main__':
    unittest.main()
