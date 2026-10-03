import unittest
import tempfile
import json
from pathlib import Path
from backend.collector.zeek_collector import ZeekCollector


class TestCyberOrbitZeekCollector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_dir = Path(self.temp_dir.name)
        self.collector = ZeekCollector(log_dir=self.log_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_zeek_tsv_conn_log(self):
        """Verify parsing standard tab-separated Zeek conn.log file"""
        conn_log_content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\n"
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\n"
            "1790870243.60\tC123456\t192.168.1.100\t54321\t10.0.0.1\t443\ttcp\thttps\t2.5\t1500\t4500\tSF\tShADadfF\t12\t18\n"
        )
        conn_path = self.log_dir / "conn.log"
        with open(conn_path, "w", encoding="utf-8") as f:
            f.write(conn_log_content)

        events = self.collector.process_file(conn_path)
        self.assertEqual(len(events), 1)

        ev = events[0]
        self.assertEqual(ev["source_ip"], "192.168.1.100")
        self.assertEqual(ev["source_port"], 54321)
        self.assertEqual(ev["destination_ip"], "10.0.0.1")
        self.assertEqual(ev["destination_port"], 443)
        self.assertEqual(ev["protocol"], "tcp")
        self.assertEqual(ev["source"], "zeek")
        self.assertEqual(ev["bytes_in"], 1500)
        self.assertEqual(ev["bytes_out"], 4500)

    def test_parse_zeek_json_format(self):
        """Verify parsing modern Zeek JSON formatted log line"""
        json_log = {
            "ts": 1790870300.0,
            "uid": "C999999",
            "id.orig_h": "172.16.0.50",
            "id.orig_p": 49152,
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 53,
            "proto": "udp",
            "service": "dns",
            "query": "malicious-c2.example.com",
            "qtype_name": "A",
            "_path": "dns",
        }
        dns_path = self.log_dir / "dns.log"
        with open(dns_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(json_log) + "\n")

        events = self.collector.process_file(dns_path)
        self.assertEqual(len(events), 1)

        ev = events[0]
        self.assertEqual(ev["source_ip"], "172.16.0.50")
        self.assertEqual(ev["destination_ip"], "10.0.0.5")
        self.assertIn("DNS A malicious-c2.example.com", ev["application"])

    def test_deduplication(self):
        """Verify deduplication prevents inserting duplicate raw Zeek events"""
        conn_log_content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\n"
            "1790870243.60\tC123456\t192.168.1.100\t54321\t10.0.0.1\t443\ttcp\thttps\t2.5\t1500\t4500\tSF\tShADadfF\t12\t18\n"
        )
        conn_path = self.log_dir / "conn.log"
        with open(conn_path, "w", encoding="utf-8") as f:
            f.write(conn_log_content)

        # First run
        events1 = self.collector.run_once()
        self.assertEqual(len(events1), 1)

        # Second run on unchanged file -> should yield 0 new events
        events2 = self.collector.run_once()
        self.assertEqual(len(events2), 0)

    def test_supported_zeek_logs_ingestion(self):
        """Verify support across conn.log, dns.log, http.log, ssl.log, and notice.log"""
        for log_name in ["conn.log", "dns.log", "http.log", "ssl.log", "notice.log"]:
            json_record = {
                "ts": 1790870500.0,
                "uid": f"UID-{log_name}",
                "id.orig_h": "192.168.1.200",
                "id.orig_p": 50000,
                "id.resp_h": "10.0.0.100",
                "id.resp_p": 80,
                "proto": "tcp",
                "_path": log_name.replace(".log", ""),
            }
            with open(self.log_dir / log_name, "w", encoding="utf-8") as f:
                f.write(json.dumps(json_record) + "\n")

        events = self.collector.run_once()
        self.assertEqual(len(events), 5)


if __name__ == "__main__":
    unittest.main()
