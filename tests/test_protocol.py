"""Protocol tests, runnable without Home Assistant: python3 -m unittest discover tests"""

from datetime import date, datetime
import importlib.util
from pathlib import Path
import sys
import unittest

_path = Path(__file__).parent.parent / "custom_components/sanitas_sbf73/protocol.py"
_spec = importlib.util.spec_from_file_location("protocol", _path)
p = sys.modules["protocol"] = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p)


class ParseTest(unittest.TestCase):
    def test_weight(self):
        m = p.parse_weight(bytes.fromhex("0eb23eea070a11072d0001f8000807"))
        self.assertEqual(m.weight_kg, 80.25)
        self.assertEqual(m.timestamp, datetime(2026, 10, 17, 7, 45, 0))
        self.assertEqual(m.user_index, 1)
        self.assertEqual(m.bmi, 24.8)
        self.assertEqual(m.height_m, 1.8)

    def test_body_composition(self):
        m = p.parse_body_composition(bytes.fromhex("9803e100841c7e01b42d28235014"))
        self.assertEqual(m.fat_pct, 22.5)
        self.assertEqual(m.bmr_kcal, 1744)
        self.assertEqual(m.muscle_pct, 38.2)
        self.assertEqual(m.soft_lean_mass_kg, 58.5)
        self.assertEqual(m.water_mass_kg, 45.0)
        self.assertEqual(m.impedance_ohm, 520.0)

    def test_merge_and_derived(self):
        m = p.parse_weight(bytes.fromhex("0eb23eea070a11072d0001f8000807"))
        m.merge(p.parse_body_composition(bytes.fromhex("9803e100841c7e01b42d28235014")))
        self.assertEqual(m.weight_kg, 80.25)
        self.assertEqual(m.water_pct, 56.1)
        self.assertEqual(m.bone_mass_kg, 3.69)

    def test_short_payload(self):
        with self.assertRaises(p.ProtocolError):
            p.parse_weight(b"\x0e\xb2")

    def test_ucp(self):
        r = p.parse_ucp_response(bytes.fromhex("20010103"))
        self.assertEqual((r.request, r.ok, r.user_index), (p.UCP_REGISTER_NEW_USER, True, 3))
        r = p.parse_ucp_response(bytes.fromhex("200205"))
        self.assertEqual((r.request, r.result), (p.UCP_CONSENT, p.UCP_USER_NOT_AUTHORIZED))

    def test_user_list(self):
        u = p.parse_user_list_entry(bytes.fromhex("000241424fc6070101af0103"))
        self.assertEqual(u, p.ScaleUser(2, "ABO", date(1990, 1, 1), 175, 1, 3))
        self.assertEqual(p.parse_user_list_entry(b"\x01"), p.USER_LIST_COMPLETE)
        self.assertEqual(p.parse_user_list_entry(b"\x11"), p.PIN_SHOWN)
        u = p.parse_user_list_entry(bytes.fromhex("0003ffffffc6070101af0103"))
        self.assertEqual(u.initials, "")


class BuildTest(unittest.TestCase):
    def test_ucp(self):
        self.assertEqual(p.build_register_new_user(4321).hex(), "01e110")
        self.assertEqual(p.build_consent(3, 4321).hex(), "0203e110")
        with self.assertRaises(ValueError):
            p.build_consent(1, 10000)

    def test_current_time(self):
        # Saturday
        self.assertEqual(
            p.build_current_time(datetime(2026, 10, 17, 8, 30, 15)).hex(), "ea070a11081e0f060000"
        )

    def test_user_data(self):
        self.assertEqual(p.build_date_of_birth(date(1990, 1, 1)).hex(), "c6070101")
        self.assertEqual(p.build_height(175).hex(), "af")
        self.assertEqual(p.build_initials("fc").hex(), "464320")
        self.assertEqual(p.build_initials("Jean-Luc").hex(), "4a4541")
        self.assertEqual(p.build_db_change_increment(1).hex(), "01000000")


if __name__ == "__main__":
    unittest.main()
