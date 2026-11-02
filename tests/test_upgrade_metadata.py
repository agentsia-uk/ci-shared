import io
import json
import unittest
from unittest.mock import patch

from code_health import cli


class UpgradeMetadataTests(unittest.TestCase):
    def test_read_page_bounds_bytes_and_record_count(self):
        with patch.object(cli, 'MAX_UPGRADE_PAGE_BYTES', 32):
            self.assertEqual(cli.read_upgrade_page(io.BytesIO(b'[{},{}]')), [{}, {}])
            with self.assertRaisesRegex(ValueError, 'exceeds'):
                cli.read_upgrade_page(io.BytesIO(b' ' * 33))
        with self.assertRaisesRegex(ValueError, 'invalid'):
            cli.read_upgrade_page(io.BytesIO(json.dumps([{}] * 101).encode()))
        for data in (b'{}', b'not-json', b'\xff'):
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, 'invalid'):
                cli.read_upgrade_page(io.BytesIO(data))


if __name__ == '__main__':
    unittest.main()
