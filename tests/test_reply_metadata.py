import json,tempfile,unittest
from pathlib import Path
from src.telegram_reader import TelegramWebReader
from src.archive_replay import load_archives

class ReplyMetadataTests(unittest.TestCase):
    def test_web_quote_is_metadata_not_current_message(self):
        html='<div class="tgme_widget_message_wrap"><div data-post="monitor1654/2"><a class="tgme_widget_message_reply" href="https://t.me/monitor1654/1"><div class="tgme_widget_message_text js-message_reply_text">Пуски КАБ</div></a><div class="tgme_widget_message_text">Ціль над містом</div><time datetime="2026-10-12T18:00:00+00:00"></time></div>'
        message=TelegramWebReader.parse_messages(html,'monitor1654')[0]
        self.assertEqual(message['text'],'Ціль над містом')
        self.assertEqual(message['reply_to'],'monitor1654/1')
        self.assertEqual(message['reply_text'],'Пуски КАБ')

    def test_export_reply_id_survives_archive_loading(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'archive.json'
            path.write_text(json.dumps(dict(username='monitor1654',messages=[dict(id=2,text='Ціль над містом',date_unixtime='1000',reply_to_message_id=1)])),encoding='utf-8')
            self.assertEqual(load_archives([path])[0]['reply_to'],'monitor1654/1')
