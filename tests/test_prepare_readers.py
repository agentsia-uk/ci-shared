import sys
import unittest
from unittest.mock import patch

from code_health import prepare_readers


class PrepareReadersTests(unittest.TestCase):
    def test_unsupported_architecture_is_refused_before_download(self):
        with patch.object(sys, 'argv', ['prepare-readers', '--destination', '/unused']), \
                patch.object(sys, 'platform', 'linux'), \
                patch.object(prepare_readers.platform, 'machine', return_value='unsupported'), \
                patch.object(prepare_readers, 'download_reader_archives') as download:
            with self.assertRaisesRegex(ValueError, 'architecture is not supported'):
                prepare_readers.main()
            download.assert_not_called()


if __name__ == '__main__':
    unittest.main()
