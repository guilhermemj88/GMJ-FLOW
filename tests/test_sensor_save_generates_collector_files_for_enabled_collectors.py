import unittest


class SensorSaveGeneratesCollectorFilesTest(unittest.TestCase):
    def test_sensor_save_generates_collector_files_for_enabled_collectors(self):
        from tests.test_collector_apply_static import CollectorApplyStaticTest

        CollectorApplyStaticTest.test_sensor_save_generates_collector_files_for_enabled_collectors(self)
