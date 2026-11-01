"""The fixture copier must not expand an explicit public manifest."""
import tempfile
import unittest
from pathlib import Path
from staging_rehearsal import read_manifest


class ManifestTests(unittest.TestCase):
    def test_unlisted_content_is_not_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'index.html').write_text('public')
            (root/'private.txt').write_text('private')
            manifest=root/'manifest'
            manifest.write_text('index.html\n')
            self.assertEqual(read_manifest(root,manifest),{'index.html':b'public'})

    def test_escape_links_duplicates_and_missing_index_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'index.html').write_text('public')
            (root/'linked.html').symlink_to(root/'index.html')
            (root/'nested').symlink_to(root,target_is_directory=True)
            manifest=root/'manifest'
            for entries in ('../index.html\n','index.html\nindex.html\n',
                            'index.html\nlinked.html\n','index.html\nnested/index.html\n',
                            'index.html\n.private\n','index.html\nrelease-a.txt\n','linked.html\n'):
                manifest.write_text(entries)
                with self.assertRaises(RuntimeError):read_manifest(root,manifest)


if __name__=='__main__':unittest.main()
