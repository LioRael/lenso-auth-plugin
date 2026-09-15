#!/usr/bin/env python3
"""Protect statement boundaries before generated SQL reaches D1 batch()."""
import runpy
import unittest
from pathlib import Path

offsets = runpy.run_path(str(Path(__file__).with_name('generate-migrations.py')))['offsets']

class StatementBoundaries(unittest.TestCase):
    def test_quotes_comments_triggers_and_utf8(self):
        statements = [
            "-- comment ;\r\nCREATE TABLE example(value TEXT);",
            "\r\nINSERT INTO example VALUES('文字;it''s quoted');",
            "\r\nCREATE TRIGGER audit AFTER INSERT ON example BEGIN UPDATE example SET value='trigger;'; SELECT 1; END;\r\n",
        ]
        sql = ''.join(statements)
        ends = offsets(sql)
        raw = sql.encode()
        starts = [0, *ends[:-1]]
        self.assertEqual([raw[start:end].decode() for start, end in zip(starts, ends)], statements)

    def test_unterminated_sql_is_rejected(self):
        with self.assertRaises(ValueError):
            offsets("SELECT 'unterminated;")

if __name__ == '__main__':
    unittest.main()
