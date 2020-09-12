import unittest
from contextlib import contextmanager

from src.cidr.cidr_calculator import CidrCalculator


@contextmanager
def resource_manager(p=0,d=0,r=0,i=0,e=0):
    routable_cidr = CidrCalculator(private=int(p), data=int(d), replication=int(r), ingress=int(i), egress=int(e))
    yield routable_cidr

test_cases = [
            {"p": 26, "d": 28, "r": 0, "expected_ip_space": 240, "expected_subnet_mask": 23, "expected_subnets": {'PrivateSubnets': '10.0.0.0/26,10.0.0.64/26,10.0.0.128/26', 'DataSubnets': '10.0.0.192/28,10.0.0.208/28,10.0.0.224/28', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 25, "d": 28, "r": 0, "expected_ip_space": 432, "expected_subnet_mask": 23, "expected_subnets": {'PrivateSubnets': '10.0.0.0/25,10.0.0.128/25,10.0.1.0/25', 'DataSubnets': '10.0.1.128/28,10.0.1.144/28,10.0.1.160/28', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 24, "d": 28, "r": 0, "expected_ip_space": 816, "expected_subnet_mask": 22, "expected_subnets": {'PrivateSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'DataSubnets': '10.0.3.0/28,10.0.3.16/28,10.0.3.32/28', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 23, "d": 28, "r": 0, "expected_ip_space": 1584, "expected_subnet_mask": 21, "expected_subnets": {'PrivateSubnets': '10.0.0.0/23,10.0.2.0/23,10.0.4.0/23', 'DataSubnets': '10.0.6.0/28,10.0.6.16/28,10.0.6.32/28', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 26, "d": 27, "r": 0, "expected_ip_space": 288, "expected_subnet_mask": 23, "expected_subnets": {'PrivateSubnets': '10.0.0.0/26,10.0.0.64/26,10.0.0.128/26', 'DataSubnets': '10.0.0.192/27,10.0.0.224/27,10.0.1.0/27', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 25, "d": 27, "r": 0, "expected_ip_space": 480, "expected_subnet_mask": 23, "expected_subnets": {'PrivateSubnets': '10.0.0.0/25,10.0.0.128/25,10.0.1.0/25', 'DataSubnets': '10.0.1.128/27,10.0.1.160/27,10.0.1.192/27', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 24, "d": 27, "r": 0, "expected_ip_space": 864, "expected_subnet_mask": 22, "expected_subnets": {'PrivateSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'DataSubnets': '10.0.3.0/27,10.0.3.32/27,10.0.3.64/27', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 23, "d": 27, "r": 0, "expected_ip_space": 1632, "expected_subnet_mask": 21, "expected_subnets": {'PrivateSubnets': '10.0.0.0/23,10.0.2.0/23,10.0.4.0/23', 'DataSubnets': '10.0.6.0/27,10.0.6.32/27,10.0.6.64/27', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 26, "d": 26, "r": 0, "expected_ip_space": 384, "expected_subnet_mask": 23, "expected_subnets": {'PrivateSubnets': '10.0.0.0/26,10.0.0.64/26,10.0.0.128/26', 'DataSubnets': '10.0.0.192/26,10.0.1.0/26,10.0.1.64/26', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 25, "d": 26, "r": 0, "expected_ip_space": 576, "expected_subnet_mask": 22, "expected_subnets": {'PrivateSubnets': '10.0.0.0/25,10.0.0.128/25,10.0.1.0/25', 'DataSubnets': '10.0.1.128/26,10.0.1.192/26,10.0.2.0/26', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 24, "d": 26, "r": 0, "expected_ip_space": 960, "expected_subnet_mask": 22, "expected_subnets": {'PrivateSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'DataSubnets': '10.0.3.0/26,10.0.3.64/26,10.0.3.128/26', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 23, "d": 26, "r": 0, "expected_ip_space": 1728, "expected_subnet_mask": 21, "expected_subnets": {'PrivateSubnets': '10.0.0.0/23,10.0.2.0/23,10.0.4.0/23', 'DataSubnets': '10.0.6.0/26,10.0.6.64/26,10.0.6.128/26', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 26, "d": 25, "r": 0, "expected_ip_space": 576, "expected_subnet_mask": 22, "expected_subnets": {'DataSubnets': '10.0.0.0/25,10.0.0.128/25,10.0.1.0/25', 'PrivateSubnets': '10.0.1.128/26,10.0.1.192/26,10.0.2.0/26', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 25, "d": 25, "r": 0, "expected_ip_space": 768, "expected_subnet_mask": 22, "expected_subnets": {'PrivateSubnets': '10.0.0.0/25,10.0.0.128/25,10.0.1.0/25', 'DataSubnets': '10.0.1.128/25,10.0.2.0/25,10.0.2.128/25', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 24, "d": 25, "r": 0, "expected_ip_space": 1152, "expected_subnet_mask": 21, "expected_subnets": {'PrivateSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'DataSubnets': '10.0.3.0/25,10.0.3.128/25,10.0.4.0/25', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 23, "d": 25, "r": 0, "expected_ip_space": 1920, "expected_subnet_mask": 21, "expected_subnets": {'PrivateSubnets': '10.0.0.0/23,10.0.2.0/23,10.0.4.0/23', 'DataSubnets': '10.0.6.0/25,10.0.6.128/25,10.0.7.0/25', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 26, "d": 24, "r": 0, "expected_ip_space": 960, "expected_subnet_mask": 22, "expected_subnets": {'DataSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'PrivateSubnets': '10.0.3.0/26,10.0.3.64/26,10.0.3.128/26', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 25, "d": 24, "r": 0, "expected_ip_space": 1152, "expected_subnet_mask": 21, "expected_subnets": {'DataSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'PrivateSubnets': '10.0.3.0/25,10.0.3.128/25,10.0.4.0/25', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 24, "d": 24, "r": 0, "expected_ip_space": 1536, "expected_subnet_mask": 21, "expected_subnets": {'PrivateSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'DataSubnets': '10.0.3.0/24,10.0.4.0/24,10.0.5.0/24', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 23, "d": 24, "r": 0, "expected_ip_space": 2304, "expected_subnet_mask": 20, "expected_subnets": {'PrivateSubnets': '10.0.0.0/23,10.0.2.0/23,10.0.4.0/23', 'DataSubnets': '10.0.6.0/24,10.0.7.0/24,10.0.8.0/24', 'ReplicationSubnets': 'na,na,na'}},
            {"p": 26, "d": 28, "r": 28, "expected_ip_space": 288, "expected_subnet_mask": 23, "expected_subnets": {'PrivateSubnets': '10.0.0.0/26,10.0.0.64/26,10.0.0.128/26', 'DataSubnets': '10.0.0.192/28,10.0.0.208/28,10.0.0.224/28', 'ReplicationSubnets': '10.0.0.240/28,10.0.1.0/28,10.0.1.16/28'}},
            {"p": 25, "d": 28, "r": 28, "expected_ip_space": 480, "expected_subnet_mask": 23, "expected_subnets": {'PrivateSubnets': '10.0.0.0/25,10.0.0.128/25,10.0.1.0/25', 'DataSubnets': '10.0.1.128/28,10.0.1.144/28,10.0.1.160/28', 'ReplicationSubnets': '10.0.1.176/28,10.0.1.192/28,10.0.1.208/28'}},
            {"p": 24, "d": 28, "r": 28, "expected_ip_space": 864, "expected_subnet_mask": 22, "expected_subnets": {'PrivateSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'DataSubnets': '10.0.3.0/28,10.0.3.16/28,10.0.3.32/28', 'ReplicationSubnets': '10.0.3.48/28,10.0.3.64/28,10.0.3.80/28'}},
            {"p": 23, "d": 28, "r": 28, "expected_ip_space": 1632, "expected_subnet_mask": 21, "expected_subnets": {'PrivateSubnets': '10.0.0.0/23,10.0.2.0/23,10.0.4.0/23', 'DataSubnets': '10.0.6.0/28,10.0.6.16/28,10.0.6.32/28', 'ReplicationSubnets': '10.0.6.48/28,10.0.6.64/28,10.0.6.80/28'}},
            {"p": 26, "d": 27, "r": 28, "expected_ip_space": 336, "expected_subnet_mask": 23, "expected_subnets": {'PrivateSubnets': '10.0.0.0/26,10.0.0.64/26,10.0.0.128/26', 'DataSubnets': '10.0.0.192/27,10.0.0.224/27,10.0.1.0/27', 'ReplicationSubnets': '10.0.1.32/28,10.0.1.48/28,10.0.1.64/28'}},
            {"p": 25, "d": 27, "r": 28, "expected_ip_space": 528, "expected_subnet_mask": 22, "expected_subnets": {'PrivateSubnets': '10.0.0.0/25,10.0.0.128/25,10.0.1.0/25', 'DataSubnets': '10.0.1.128/27,10.0.1.160/27,10.0.1.192/27', 'ReplicationSubnets': '10.0.1.224/28,10.0.1.240/28,10.0.2.0/28'}},
            {"p": 24, "d": 27, "r": 28, "expected_ip_space": 912, "expected_subnet_mask": 22, "expected_subnets": {'PrivateSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'DataSubnets': '10.0.3.0/27,10.0.3.32/27,10.0.3.64/27', 'ReplicationSubnets': '10.0.3.96/28,10.0.3.112/28,10.0.3.128/28'}},
            {"p": 23, "d": 27, "r": 28, "expected_ip_space": 1680, "expected_subnet_mask": 21, "expected_subnets": {'PrivateSubnets': '10.0.0.0/23,10.0.2.0/23,10.0.4.0/23', 'DataSubnets': '10.0.6.0/27,10.0.6.32/27,10.0.6.64/27', 'ReplicationSubnets': '10.0.6.96/28,10.0.6.112/28,10.0.6.128/28'}},
            {"p": 26, "d": 26, "r": 28, "expected_ip_space": 432, "expected_subnet_mask": 23, "expected_subnets": {'PrivateSubnets': '10.0.0.0/26,10.0.0.64/26,10.0.0.128/26', 'DataSubnets': '10.0.0.192/26,10.0.1.0/26,10.0.1.64/26', 'ReplicationSubnets': '10.0.1.128/28,10.0.1.144/28,10.0.1.160/28'}},
            {"p": 25, "d": 26, "r": 28, "expected_ip_space": 624, "expected_subnet_mask": 22, "expected_subnets": {'PrivateSubnets': '10.0.0.0/25,10.0.0.128/25,10.0.1.0/25', 'DataSubnets': '10.0.1.128/26,10.0.1.192/26,10.0.2.0/26', 'ReplicationSubnets': '10.0.2.64/28,10.0.2.80/28,10.0.2.96/28'}},
            {"p": 24, "d": 26, "r": 28, "expected_ip_space": 1008, "expected_subnet_mask": 22, "expected_subnets": {'PrivateSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'DataSubnets': '10.0.3.0/26,10.0.3.64/26,10.0.3.128/26', 'ReplicationSubnets': '10.0.3.192/28,10.0.3.208/28,10.0.3.224/28'}},
            {"p": 23, "d": 26, "r": 28, "expected_ip_space": 1776, "expected_subnet_mask": 21, "expected_subnets": {'PrivateSubnets': '10.0.0.0/23,10.0.2.0/23,10.0.4.0/23', 'DataSubnets': '10.0.6.0/26,10.0.6.64/26,10.0.6.128/26', 'ReplicationSubnets': '10.0.6.192/28,10.0.6.208/28,10.0.6.224/28'}},
            {"p": 26, "d": 25, "r": 28, "expected_ip_space": 624, "expected_subnet_mask": 22, "expected_subnets": {'DataSubnets': '10.0.0.0/25,10.0.0.128/25,10.0.1.0/25', 'PrivateSubnets': '10.0.1.128/26,10.0.1.192/26,10.0.2.0/26', 'ReplicationSubnets': '10.0.2.64/28,10.0.2.80/28,10.0.2.96/28'}},
            {"p": 25, "d": 25, "r": 28, "expected_ip_space": 816, "expected_subnet_mask": 22, "expected_subnets": {'PrivateSubnets': '10.0.0.0/25,10.0.0.128/25,10.0.1.0/25', 'DataSubnets': '10.0.1.128/25,10.0.2.0/25,10.0.2.128/25', 'ReplicationSubnets': '10.0.3.0/28,10.0.3.16/28,10.0.3.32/28'}},
            {"p": 24, "d": 25, "r": 28, "expected_ip_space": 1200, "expected_subnet_mask": 21, "expected_subnets": {'PrivateSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'DataSubnets': '10.0.3.0/25,10.0.3.128/25,10.0.4.0/25', 'ReplicationSubnets': '10.0.4.128/28,10.0.4.144/28,10.0.4.160/28'}},
            {"p": 23, "d": 25, "r": 28, "expected_ip_space": 1968, "expected_subnet_mask": 21, "expected_subnets": {'PrivateSubnets': '10.0.0.0/23,10.0.2.0/23,10.0.4.0/23', 'DataSubnets': '10.0.6.0/25,10.0.6.128/25,10.0.7.0/25', 'ReplicationSubnets': '10.0.7.128/28,10.0.7.144/28,10.0.7.160/28'}},
            {"p": 26, "d": 24, "r": 28, "expected_ip_space": 1008, "expected_subnet_mask": 22, "expected_subnets": {'DataSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'PrivateSubnets': '10.0.3.0/26,10.0.3.64/26,10.0.3.128/26', 'ReplicationSubnets': '10.0.3.192/28,10.0.3.208/28,10.0.3.224/28'}},
            {"p": 25, "d": 24, "r": 28, "expected_ip_space": 1200, "expected_subnet_mask": 21, "expected_subnets": {'DataSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'PrivateSubnets': '10.0.3.0/25,10.0.3.128/25,10.0.4.0/25', 'ReplicationSubnets': '10.0.4.128/28,10.0.4.144/28,10.0.4.160/28'}},
            {"p": 24, "d": 24, "r": 28, "expected_ip_space": 1584, "expected_subnet_mask": 21, "expected_subnets": {'PrivateSubnets': '10.0.0.0/24,10.0.1.0/24,10.0.2.0/24', 'DataSubnets': '10.0.3.0/24,10.0.4.0/24,10.0.5.0/24', 'ReplicationSubnets': '10.0.6.0/28,10.0.6.16/28,10.0.6.32/28'}},
            {"p": 23, "d": 24, "r": 28, "expected_ip_space": 2352, "expected_subnet_mask": 20, "expected_subnets": {'PrivateSubnets': '10.0.0.0/23,10.0.2.0/23,10.0.4.0/23', 'DataSubnets': '10.0.6.0/24,10.0.7.0/24,10.0.8.0/24', 'ReplicationSubnets': '10.0.9.0/28,10.0.9.16/28,10.0.9.32/28'}},
            {"p": 23, "d": 22, "r": 28, "expected_ip_space": 4656, "expected_subnet_mask": 19, "expected_subnets": {'DataSubnets': '10.0.0.0/22,10.0.4.0/22,10.0.8.0/22', 'PrivateSubnets': '10.0.12.0/23,10.0.14.0/23,10.0.16.0/23', 'ReplicationSubnets': '10.0.18.0/28,10.0.18.16/28,10.0.18.32/28'}},
        ]


class CidrCalculatorTesting(unittest.TestCase):

    def setUp(self):
        print(self._testMethodDoc)

    def test_get_subnets_size_and_subnets_for_routable_cidr(self):
        '''Check ip_space, subnet_mask, and subnet attributes for routable CIDR.'''

        for test_case in test_cases:
            with resource_manager(p=test_case["p"], d=test_case["d"], r=test_case["r"]) as resource:
                self.resource = resource
                self.assertEqual(test_case["expected_ip_space"], self.resource.ip_space)
                self.assertEqual(test_case["expected_subnet_mask"], self.resource.subnet_mask)
                self._subnet_with_mask="10.0.0.0/" + str(test_case["expected_subnet_mask"])
                self.assertEqual(test_case["expected_subnets"], self.resource.get_subnets(self._subnet_with_mask))

    def test_get_subnet_size_and_subnets_for_non_routable_cidr(self):
        '''Check ip_space, subnet_mask, and subnet attributes for non-routable CIDR.'''
        with resource_manager(i=22, e=28) as resource:
            self.resource = resource
            self.assertEqual(3120, self.resource.ip_space)
            self.assertEqual(20, self.resource.subnet_mask)
            self.assertEqual({'IngressSubnets': '10.0.0.0/22,10.0.4.0/22,10.0.8.0/22',
                              'EgressSubnets': '10.0.12.0/28,10.0.12.16/28,10.0.12.32/28',
                              'ReplicationSubnets': 'na,na,na'}, self.resource.get_subnets('10.0.0.0/20'))


if __name__ == '__main__':
     unittest.main()
