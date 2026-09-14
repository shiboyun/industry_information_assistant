"""业务化安全评测，全部使用本地假工具。"""
import unittest

from security_business_samples import build_business_samples, evaluate_samples


class SecurityBusinessSampleTests(unittest.TestCase):
    def test_structured_business_samples(self):
        samples = build_business_samples()
        self.assertGreaterEqual(len(samples), 80)
        report = evaluate_samples(samples)
        self.assertEqual(report["sample_count"], 92)
        # 这条此前没有被断言，导致招牌指标「安全决策符合预期 N 条」没有回归保护
        self.assertEqual(report["decision_pass_count"], 92)
        self.assertEqual(report["duplicate_execution_count"], 0)
        self.assertTrue(report["hash_chain_verified"])
        self.assertEqual(report["audit_field_completeness_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
