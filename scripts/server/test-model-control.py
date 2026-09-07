import os
import tempfile
import time
import unittest
from shieldchain.qwen_experience.model_control import catalog, select, inference, lock, write, read, ControlError

class ModelControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.environ['QWEN_CONTROL_ROOT'] = self.temp.name
        write('heartbeat.json', {'time': time.time()})
        write('state.json', {'active_model': 'qwen3', 'ready': True, 'phase': 'ready', 'message': 'ready'})
    def tearDown(self):
        self.temp.cleanup()
    def test_catalog_and_ready_inference(self):
        self.assertEqual(len(catalog()['models']), 2)
        with inference('qwen3') as served:
            self.assertEqual(served, 'shieldchain-qwen3-30b')
    def test_wrong_model_rejected(self):
        with self.assertRaises(ControlError), inference('qwen38'): pass
    def test_queue_disables_chat_and_duplicate_switch(self):
        self.assertEqual(select('qwen38')['phase'], 'queued')
        with self.assertRaises(ControlError): select('qwen3')
        with self.assertRaises(ControlError), inference('qwen3'): pass
    def test_stale_heartbeat(self):
        write('heartbeat.json', {'time': 0})
        self.assertFalse(catalog()['ready'])
        with self.assertRaises(ControlError): select('qwen38')
    def test_allowlist(self):
        with self.assertRaises(ControlError): select('../../etc')
        self.assertEqual(read('request.json'), {})
    def test_missing_switch_permission_keeps_active_chat_available(self):
        write('heartbeat.json', {'time': time.time(), 'can_switch': False})
        self.assertTrue(catalog()['ready'])
        self.assertFalse(catalog()['can_switch'])
        with inference('qwen3'): pass
        with self.assertRaises(ControlError): select('qwen38')
    def test_exclusive_switch_blocks_inference(self):
        with lock('inference.lock'):
            with self.assertRaises(ControlError), inference('qwen3'): pass
    def test_reselect_active_no_restart(self):
        self.assertTrue(select('qwen3')['ready'])
        self.assertEqual(read('request.json'), {})

if __name__ == '__main__': unittest.main()
